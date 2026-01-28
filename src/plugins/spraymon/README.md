# Spraymon Plugin

## Overview

The spraymon plugin detects potential heap spray attacks by monitoring GDI and USER handle counts in Windows processes. Heap spraying is a technique commonly used in exploitation where an attacker allocates many objects to fill memory with controlled data, often targeting GDI or USER objects in the Windows GUI subsystem.

The plugin works by:
1. Hooking the `PsSetProcessWin32Process` kernel function to monitor when processes are being cleaned up (when the Win32Process pointer is set to NULL)
2. Reading the peak GDI and USER handle counts from the `_W32PROCESS` structure
3. Logging an alert when either count exceeds configurable thresholds (default: 3000)
4. Performing a final analysis of all running processes when DRAKVUF stops to catch any suspicious activity that may have been missed

High counts of GDI or USER objects can indicate:
- Heap spray attacks targeting the Windows GUI subsystem
- Exploit attempts leveraging GDI object allocation primitives
- Resource exhaustion attacks

## Supported Operating Systems

- **Windows 7**: Fully supported
- **Windows 10**: Supported for builds >= 14393 (version 1607 Anniversary Update and later)
- **Linux**: Not supported

The plugin requires access to Windows kernel structures (`_EPROCESS`, `_W32PROCESS`) and the win32k.sys driver, making it Windows-specific.

## Configuration Options

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `win32k_profile` | Path to the JSON debug profile for win32k.sys | N/A | Yes |
| `gdi_threshold` | GDI handle count threshold for alerting | 3000 | No |
| `usr_threshold` | USER handle count threshold for alerting | 3000 | No |

The win32k.sys JSON profile must contain symbol information for the `_W32PROCESS` structure, specifically:
- `GDIHandleCountPeak` - Peak count of GDI handles allocated by the process
- `UserHandleCountPeak` - Peak count of USER handles allocated by the process

## How to Enable the Plugin

### Meson Build System

The plugin is enabled by default. To explicitly control it:

```bash
# Enable (default)
meson configure -Dplugin-spraymon=true

# Disable
meson configure -Dplugin-spraymon=false
```

### Autotools Build System

```bash
# Enable (default)
./configure --enable-plugin-spraymon

# Disable
./configure --disable-plugin-spraymon
```

### Runtime Requirements

When running DRAKVUF, provide the win32k.sys profile using the appropriate command-line option (typically `-w` or `--win32k-profile`).

## Output Format

The plugin outputs events when a process's peak GDI or USER handle count exceeds the configured thresholds.

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| PID | Process ID of the suspicious process |
| ProcessName | Name of the process (quoted string) |
| Reason | Description of why the alert was triggered ("High graphic objects count") |

## Example Output

### Default Format

```
[SPRAYMON] PID:1234 ProcessName:"malware.exe" Reason:"High graphic objects count"
```

### JSON Format

```json
{"Plugin":"spraymon","PID":1234,"ProcessName":"malware.exe","Reason":"High graphic objects count"}
```

## Detection Scenarios

The spraymon plugin is useful for detecting:

1. **GDI Object Heap Sprays**: Exploits that allocate many GDI objects (bitmaps, palettes, etc.) to achieve controlled memory layouts
2. **USER Object Heap Sprays**: Similar attacks using USER objects (windows, menus, etc.)
3. **Kernel Pool Sprays**: Some kernel exploitation techniques spray GDI/USER objects to manipulate kernel pool layouts
4. **Resource Exhaustion**: Denial-of-service attacks that exhaust system GDI/USER handle limits

## Technical Details

The plugin operates in two modes:

1. **Real-time Monitoring**: Hooks `PsSetProcessWin32Process` to catch process termination events. When a process's Win32Process pointer is being cleared (set to NULL), the plugin reads the peak handle counts before they are lost.

2. **Final Analysis**: When DRAKVUF stops, the plugin enumerates all running processes and checks their current peak handle counts, ensuring no suspicious activity is missed.

The plugin reads the following Windows kernel structures:
- `_EPROCESS.Win32Process` - Pointer to the process's Win32 subsystem data
- `_W32PROCESS.GDIHandleCountPeak` - Maximum GDI handle count reached during process lifetime
- `_W32PROCESS.UserHandleCountPeak` - Maximum USER handle count reached during process lifetime

Reference: https://www.geoffchappell.com/studies/windows/km/win32k/structs/processinfo/index.htm
