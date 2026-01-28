# Object Monitor Plugin (objmon)

## Overview

The objmon plugin monitors Windows kernel object operations by hooking into the following functions:

1. **ObCreateObject** - Monitors kernel object creation. This function is called when a new kernel object is being created and captures the object type key (a 4-character identifier stored in the `_OBJECT_TYPE` structure).

2. **NtDuplicateObject** - Monitors handle duplication operations. This function is used by processes to duplicate handles between processes, which can be used for inter-process communication or handle inheritance.

This plugin is useful for tracking object lifecycle events and detecting suspicious handle duplication that may indicate process injection or other malicious activities.

## Supported Operating Systems

- **Windows**: Fully supported
- **Linux**: Not supported (the plugin hooks Windows-specific kernel functions)

## Configuration Options

The plugin supports the following command-line options:

| Option | Description |
|--------|-------------|
| `--objmon-disable-create-hook` | Disables the ObCreateObject hook (object creation monitoring) |
| `--objmon-disable-duplicate-hook` | Disables the NtDuplicateObject hook (handle duplication monitoring) |

## How to Enable the Plugin

The plugin is enabled by default in the meson build system.

### Build Configuration

In `meson_options.txt`, the plugin is controlled by:

```
option('plugin-objmon', type : 'boolean', value : true)
```

To disable the plugin at build time:

```bash
meson setup build -Dplugin-objmon=false
```

To enable the plugin (default):

```bash
meson setup build -Dplugin-objmon=true
```

### Runtime Configuration

Both hooks are enabled by default at runtime. Use the command-line options above to selectively disable specific hooks.

## Output Format

The plugin outputs events in DRAKVUF's configurable output format (default, CSV, JSON, or key-value). Each event includes common fields plus event-specific fields.

### Common Fields (all events)

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | Page table base register value (identifies the process address space) |
| Process Name | Name of the process triggering the event |
| Method | Name of the hooked function |
| SessionID | Windows session ID of the process |
| PID | Process ID |
| PPID | Parent process ID |

### ObCreateObject Event Fields

| Field | Description |
|-------|-------------|
| Key | 4-character object type key from the `_OBJECT_TYPE` structure (e.g., "Proc" for Process, "Thre" for Thread, "File" for File) |

### NtDuplicateObject Event Fields

| Field | Description |
|-------|-------------|
| SourceProcessHandle | Handle to the source process (typically -1/0xFFFFFFFF for current process) |
| SourceHandle | Handle value in the source process to be duplicated |
| TargetProcessHandle | Handle to the target process (typically -1/0xFFFFFFFF for current process) |
| TargetHandle | Newly created handle value in the target process |
| DesiredAccess | Requested access rights for the new handle (0 to copy source handle's access) |
| HandleAttributes | Attributes for the new handle (e.g., OBJ_INHERIT) |
| Options | Duplication options (DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, etc.) |

## Example Output

### Default Format

ObCreateObject event:
```
[OBJMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "explorer.exe":ObCreateObject SessionID:1 PID:1234 PPID:456 Key:"Proc"
```

NtDuplicateObject event:
```
[OBJMON] TIME:1234567890.654321 VCPU:0 CR3:0x1A2B3C4D "malware.exe":NtDuplicateObject SessionID:1 PID:5678 PPID:1234 SourceProcessHandle:0xFFFFFFFF SourceHandle:0x100 TargetProcessHandle:0x200 TargetHandle:0x300 DesiredAccess:0x1F0FFF HandleAttributes:0x0 Options:0x2
```

### JSON Format

ObCreateObject event:
```json
{"Plugin":"objmon","TimeStamp":"1234567890.123456","VCPU":0,"CR3":"0x1A2B3C4D","ProcessName":"explorer.exe","Method":"ObCreateObject","SessionID":1,"PID":1234,"PPID":456,"Key":"Proc"}
```

NtDuplicateObject event:
```json
{"Plugin":"objmon","TimeStamp":"1234567890.654321","VCPU":0,"CR3":"0x1A2B3C4D","ProcessName":"malware.exe","Method":"NtDuplicateObject","SessionID":1,"PID":5678,"PPID":1234,"SourceProcessHandle":"0xFFFFFFFF","SourceHandle":"0x100","TargetProcessHandle":"0x200","TargetHandle":"0x300","DesiredAccess":"0x1F0FFF","HandleAttributes":"0x0","Options":"0x2"}
```

## Technical Notes

- The `Key` field in ObCreateObject events is read from the `Key` member of the `_OBJECT_TYPE` structure at an offset determined dynamically from the kernel debugging symbols.
- Handle values in NtDuplicateObject are displayed in hexadecimal format.
- The NtDuplicateObject hook captures arguments on function entry and reads the output handle value on function return.
