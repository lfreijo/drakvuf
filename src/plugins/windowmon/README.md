# Windowmon Plugin

## Overview

The windowmon plugin monitors Windows window-related API calls by hooking the `NtUserFindWindowEx` function in `win32k.sys`. This allows tracking when processes search for windows by class name or window name, which is a common technique used by malware to detect analysis environments, security tools, or target specific applications.

When a process calls `FindWindow`, `FindWindowEx`, or related Win32 API functions, they ultimately invoke `NtUserFindWindowEx` in the kernel. This plugin intercepts these calls and logs the window class and window name being searched for.

## Supported Operating Systems

- **Windows**: Fully supported (requires win32k.sys JSON profile)
- **Linux**: Not supported

The plugin specifically hooks Windows kernel GUI subsystem functions and requires the `explorer.exe` process to be running for initialization (used to obtain the SSDT shadow table address).

## Configuration Options

The plugin requires the following configuration:

| Option | Description | Required |
|--------|-------------|----------|
| `win32k_profile` | Path to the JSON debug profile for win32k.sys | Yes |

The win32k.sys profile must contain symbol information for:
- `NtUserFindWindowEx` - The function to hook
- `W32pServiceTable` - Used to calculate the function address

## How to Enable the Plugin

### Meson Build System

The plugin is enabled by default. To explicitly control it:

```bash
# Enable (default)
meson configure -Dplugin-windowmon=true

# Disable
meson configure -Dplugin-windowmon=false
```

### Autotools Build System

```bash
# Enable (default)
./configure --enable-plugin-windowmon

# Disable
./configure --disable-plugin-windowmon
```

### Runtime Requirements

When running DRAKVUF, provide the win32k.sys profile using the appropriate command-line option (typically `-w` or `--win32k-profile`).

## Output Format

The plugin outputs events with the following fields:

### Common Fields (provided by DRAKVUF framework)

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | Page table base register value (process context) |
| Process Name | Name of the process that triggered the event |
| Method | The hooked function name (`NtUserFindWindowEx`) |
| SessionID | Windows session ID of the process |
| PID | Process ID |
| PPID | Parent process ID |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| Class | The window class name being searched for (quoted string, or `NULL` if not specified) |
| Name | The window title/name being searched for (quoted string, or `NULL` if not specified) |

## Example Output

### Default Format

```
[WINDOWMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "malware.exe":NtUserFindWindowEx SessionID:1 PID:1234 PPID:5678 Class:"OllyDbg" Name:NULL
```

### JSON Format

```json
{"Plugin":"windowmon","TimeStamp":"1234567890.123456","VCPU":0,"CR3":"0x1A2B3C4D","ProcessName":"malware.exe","Method":"NtUserFindWindowEx","SessionID":1,"PID":1234,"PPID":5678,"Class":"OllyDbg","Name":"NULL"}
```

### Use Cases

The windowmon plugin is particularly useful for detecting:

1. **Anti-analysis techniques**: Malware often searches for debugger windows (e.g., "OllyDbg", "x64dbg", "IDA")
2. **Security tool detection**: Searches for antivirus or sandbox windows
3. **Target application discovery**: Malware searching for banking applications, browsers, or other targets
4. **Process injection preparation**: Finding windows to inject code into

## Technical Details

The plugin works by:

1. Loading the win32k.sys JSON profile to obtain function RVAs
2. Finding the `explorer.exe` process to access the SSDT shadow table
3. Calculating the virtual address of `NtUserFindWindowEx` using the shadow SSDT
4. Setting a breakpoint trap on the function
5. Reading the window class (argument 3) and window name (argument 4) parameters when the function is called
