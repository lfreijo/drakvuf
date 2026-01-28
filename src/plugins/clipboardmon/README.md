# Clipboardmon Plugin

## Overview

The clipboardmon plugin monitors Windows clipboard-related system calls by hooking into the win32k.sys kernel module. It detects when processes interact with the system clipboard, which is useful for:

- Detecting clipboard data exfiltration attempts
- Monitoring clipboard spying behavior
- Identifying processes that register as clipboard listeners or viewers
- Tracking clipboard read and write operations

## Supported Operating Systems

**Windows only**

This plugin requires the Windows win32k.sys kernel module and hooks Windows-specific NT user functions. It is not supported on Linux or other operating systems.

## Configuration Options

The plugin requires the following configuration:

| Option | Description | Required |
|--------|-------------|----------|
| `win32k_profile` | Path to the JSON debug profile for win32k.sys | Yes |

The win32k.sys JSON profile contains symbol information needed to locate the addresses of the hooked functions.

## How to Enable the Plugin

### Meson Build Option

The plugin is enabled by default. To explicitly control it during the build:

```bash
# Enable (default)
meson configure -Dplugin-clipboardmon=true

# Disable
meson configure -Dplugin-clipboardmon=false
```

### Runtime Requirements

At runtime, you must provide the win32k.sys JSON profile using the appropriate command-line option when starting DRAKVUF.

## Monitored Functions

The plugin sets breakpoints on the following win32k.sys functions:

| Function | Description |
|----------|-------------|
| `NtUserGetClipboardData` | Called when a process reads data from the clipboard |
| `NtUserSetClipboardData` | Called when a process writes data to the clipboard |
| `NtUserAddClipboardFormatListener` | Called when a process registers to receive clipboard change notifications |
| `NtUserSetClipboardViewer` | Called when a process registers as a clipboard viewer |

## Output Format

The plugin outputs events using DRAKVUF's standard output format system, supporting DEFAULT, JSON, KV, and CSV formats.

### Output Fields

Each event contains the following common fields:

| Field | Description |
|-------|-------------|
| `Plugin` | Always "clipboardmon" |
| `TimeStamp` / `TIME` | Timestamp of the event (seconds.microseconds) |
| `PID` | Process ID of the process making the clipboard call |
| `PPID` | Parent process ID |
| `TID` | Thread ID (JSON format) |
| `UserId` / `SessionID` | Windows session ID of the process |
| `ProcessName` | Name of the process making the call |
| `Method` | The clipboard function being called (e.g., "NtUserGetClipboardData") |
| `EventUID` | Unique identifier for the event (JSON format) |
| `VCPU` | Virtual CPU number (DEFAULT/KV format) |
| `CR3` | CR3 register value (DEFAULT/KV format) |

## Example Output

### Default Format

```
[CLIPBOARDMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "notepad.exe":NtUserGetClipboardData SessionID:1 PID:1234 PPID:5678
```

### JSON Format

```json
{"Plugin":"clipboardmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":5678,"TID":4321,"UserId":1,"ProcessName":"notepad.exe","Method":"NtUserSetClipboardData","EventUID":"0x123456"}
```

### Key-Value Format

```
clipboardmon TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "notepad.exe":NtUserAddClipboardFormatListener SessionID:1 PID:1234 PPID:5678
```

## Technical Details

The plugin works by:

1. Loading the win32k.sys JSON profile to obtain function RVAs (Relative Virtual Addresses)
2. Locating the Shadow System Service Descriptor Table (SSDT) via `KeServiceDescriptorTableShadow`
3. Finding the `explorer.exe` process to obtain a valid DTB (Directory Table Base) for address translation
4. Calculating the virtual addresses of the target functions
5. Setting breakpoint traps on each function

When any of the hooked functions are called, the callback logs the event with process context information.
