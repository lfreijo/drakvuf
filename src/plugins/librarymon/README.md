# Librarymon Plugin

## Overview

The librarymon plugin monitors dynamic library loading operations in Windows virtual machines. It hooks into the Windows NT Loader (ntdll.dll) to intercept calls to `LdrLoadDll` and `LdrGetDllHandle`, providing visibility into which DLLs are being loaded or queried by processes running in the guest VM.

This plugin is useful for:
- Tracking malware behavior by observing which libraries it loads
- Detecting suspicious DLL injection attempts
- Understanding application dependencies at runtime
- Security analysis and forensics

## Supported Operating Systems

- **Windows**: Fully supported. The plugin hooks Windows-specific NT Loader functions.
- **Linux**: Not supported. The plugin requires ntdll.dll which is Windows-specific.

## Configuration Options

The plugin requires a JSON profile for ntdll.dll to locate the functions it needs to hook.

| Option | Description | Required |
|--------|-------------|----------|
| `--json-ntdll <path>` | Path to the JSON debug profile for ntdll.dll | Yes |

Without the ntdll profile, the plugin will print a debug message and fail to initialize:
```
Librarymon plugin requires the JSON debug info for ntdll.dll!
```

## How to Enable the Plugin

### Compile-time

The plugin is enabled by default. To explicitly control it during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-librarymon=true

# Disable the plugin
meson setup build -Dplugin-librarymon=false
```

When enabled, this sets the `ENABLE_PLUGIN_LIBRARYMON` preprocessor definition.

### Runtime

To use the plugin at runtime, provide the ntdll JSON profile:

```bash
drakvuf -r <rekall_profile> -d <domain> --json-ntdll /path/to/ntdll.json
```

## Output Format

The plugin outputs events when `LdrLoadDll` or `LdrGetDllHandle` is called. The output format depends on the configured output mode (default, JSON, CSV, or KV).

### Output Fields

#### Common Fields (all output formats)

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | Page table base register value (process context) |
| Process Name | Name of the process making the call |
| Method | The hooked function name (LdrLoadDll or LdrGetDllHandle) |
| SessionID | Windows session ID of the user |
| PID | Process ID |
| PPID | Parent Process ID |

#### Plugin-specific Fields

**Default Output Format:**

| Field | Description |
|-------|-------------|
| EPROCESS | Hexadecimal address of the Windows EPROCESS structure |
| MODULE_NAME | Name of the DLL being loaded/queried (quoted string) |
| MODULE_PATH | Full path to the DLL (quoted string) |

**Other Output Formats (JSON, CSV, KV):**

| Field | Description |
|-------|-------------|
| ModuleName | Name of the DLL being loaded/queried (quoted string) |
| ModulePath | Full path to the DLL (quoted string) |

## Example Output

### Default Format

```
[LIBRARYMON] TIME:1609459200.123456 VCPU:0 CR3:0x1A2B3C4D "explorer.exe":LdrLoadDll SessionID:1 PID:1234 PPID:5678 EPROCESS:0xFFFF800012345678 MODULE_NAME:"kernel32.dll" MODULE_PATH:"C:\Windows\System32\kernel32.dll"
```

### JSON Format

```json
{"Plugin":"librarymon","TimeStamp":"1609459200.123456","VCPU":0,"CR3":"0x1a2b3c4d","ProcessName":"explorer.exe","Method":"LdrLoadDll","SessionID":1,"PID":1234,"PPID":5678,"ModuleName":"kernel32.dll","ModulePath":"C:\\Windows\\System32\\kernel32.dll"}
```

## Hooked Functions

| Function | Description |
|----------|-------------|
| `LdrLoadDll` | Loads a DLL into the process address space. Arguments captured: SearchPath (arg 1), ModuleName (arg 3) |
| `LdrGetDllHandle` | Retrieves a handle to a previously loaded DLL. Arguments captured: SearchPath (arg 1), ModuleName (arg 3) |
