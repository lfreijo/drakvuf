# Crashmon Plugin

## Overview

The crashmon plugin monitors for crashed processes in a guest virtual machine by detecting when the Windows Error Reporting process (WerFault.exe) is invoked. When a process crashes in Windows, WerFault.exe is launched with command-line parameters that include the PID of the crashed process. This plugin intercepts these invocations and reports information about the crashed process.

The plugin works by setting up a trap on CR3 register changes (context switches). On each context switch, it checks if the current process is WerFault.exe and, if so, extracts the PID of the crashed process from the command line arguments. It then retrieves additional information about the crashed process (name, PPID) and outputs a crash report.

## Supported Operating Systems

- **Windows**: Fully supported. The plugin detects crashes by monitoring for WerFault.exe processes.
- **Linux**: Not supported. The `is_crashreporter` function is only implemented for Windows.

## Configuration Options

The crashmon plugin has no additional configuration options. It uses the global output format setting configured for DRAKVUF.

## How to Enable the Plugin

The plugin is enabled by default in the meson build system.

### Meson Build Option

```
option('plugin-crashmon', type : 'boolean', value : true)
```

To explicitly enable or disable during build configuration:

```bash
# Enable (default)
meson configure -Dplugin-crashmon=true builddir

# Disable
meson configure -Dplugin-crashmon=false builddir
```

When enabled, the build system sets `ENABLE_PLUGIN_CRASHMON=1` in the configuration header.

## Output Format

The plugin outputs standard DRAKVUF event information when a crash is detected. The output format depends on the global output format setting (default, JSON, CSV, or key-value).

### Output Fields

The crashmon plugin outputs the standard common fields that all DRAKVUF plugins emit:

| Field | Description |
|-------|-------------|
| Plugin | Plugin name ("crashmon") |
| TimeStamp / TIME | Timestamp of when the crash was detected (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | CR3 register value (page table base address) |
| ProcessName | Name of the WerFault.exe process that reported the crash |
| SessionID | Windows session ID of the reporting process |
| PID | Process ID of the WerFault.exe reporter process |
| PPID | Parent process ID of the WerFault.exe reporter process |
| TID | Thread ID (in JSON format) |
| UserId | User ID / Session ID |
| Method | Trap name (empty for CR3 traps) |
| EventUID | Unique event identifier (in JSON format) |

Note: The crashed process information (the PID passed to WerFault.exe via `-p` parameter, the crashed process name, and its PPID) is retrieved internally but not currently included in the output fields. The output shows information about the WerFault.exe process that detected the crash.

## Example Output

### Default Format

```
[CRASHMON] TIME:1234567890.123456 VCPU:0 CR3:0x1AA000 "WerFault.exe": SessionID:1 PID:1234 PPID:456
```

### JSON Format

```json
{"Plugin":"crashmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":456,"TID":5678,"UserId":1,"ProcessName":"WerFault.exe","Method":null,"EventUID":"0x1234abcd"}
```

### Key-Value Format

```
crashmon TIME=1234567890.123456 VCPU=0 CR3=0x1AA000 PROCNAME="WerFault.exe" SessionID=1 PID=1234 PPID=456
```

### CSV Format

```
crashmon,1234567890.123456,0,0x1AA000,WerFault.exe,,1,1234,456
```

## Technical Details

### Detection Mechanism

1. The plugin registers a CR3 register trap that fires on every context switch
2. On each trap, it calls `drakvuf_is_crashreporter()` to check if the current process is WerFault.exe
3. The `win_is_crashreporter()` function:
   - Checks if the process name contains "WerFault.exe"
   - Parses the command line to find the `-p` parameter
   - Extracts the crashed process PID from the `-p` argument
4. If a crash reporter is detected, the plugin retrieves information about the crashed process and outputs the event

### Implementation Files

- `crashmon.cpp`: Main plugin implementation
- `crashmon.h`: Plugin class definition with CR3 trap configuration
