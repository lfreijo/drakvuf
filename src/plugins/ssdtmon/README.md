# SSDTMON Plugin

## Overview

The SSDTMON (System Service Descriptor Table Monitor) plugin monitors modifications to critical Windows kernel structures used for system call dispatching. It detects tampering with:

- **SSDT (System Service Descriptor Table)**: The kernel's primary syscall table (`KiServiceTable`) containing pointers to native Windows system calls.
- **SSDT Shadow (W32pServiceTable)**: The GUI subsystem syscall table in `win32k.sys` used for graphical operations.
- **SDT (KeServiceDescriptorTable)**: The service descriptor table structure.
- **SDT Shadow (KeServiceDescriptorTableShadow)**: The shadow service descriptor table used for GUI syscalls.

This plugin is designed to detect rootkit-style attacks that hook system calls by modifying these tables, a technique commonly used by malware to intercept and manipulate system operations.

## Supported Operating Systems

- **Windows**: Fully supported
- **Linux**: Not supported

## Configuration Options

The plugin accepts the following configuration:

| Option | Description |
|--------|-------------|
| `win32k_profile` | Path to the JSON profile for `win32k.sys`. Required for monitoring the SSDT Shadow table. If not provided, only the main SSDT will be monitored. |

The `win32k_profile` can be passed via the `--win32k-profile` command-line argument to DRAKVUF.

## How to Enable the Plugin

### Meson Build Option

The plugin is enabled by default. To explicitly control it during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-ssdtmon=true

# Disable the plugin
meson setup build -Dplugin-ssdtmon=false
```

### Runtime

The plugin is automatically loaded when running DRAKVUF on a Windows guest. To enable SSDT Shadow monitoring, provide the win32k profile:

```bash
drakvuf -r /path/to/kernel.json -w /path/to/win32k.json ...
```

## Output Format

### Standard Fields

All output events include these standard fields provided by the DRAKVUF output format:

| Field | Description |
|-------|-------------|
| `Plugin` | Always "ssdtmon" |
| `TimeStamp` | Event timestamp in seconds.microseconds format |
| `PID` | Process ID that triggered the modification |
| `PPID` | Parent process ID |
| `TID` | Thread ID |
| `UserId` | User ID |
| `ProcessName` | Name of the process |
| `Method` | Trap method name (if applicable) |
| `EventUID` | Unique event identifier |

### Plugin-Specific Fields

#### Write Access Events (Real-time Detection)

When write access to an SSDT table is detected:

| Field | Type | Description |
|-------|------|-------------|
| `TableIndex` | Number | The index of the syscall entry being modified in the table |
| `Table` | String | The table being modified: `"SSDT"` or `"SSDTShadow"` |

#### Integrity Check Events (On Stop)

When DRAKVUF stops, the plugin performs integrity checks using SHA-256 checksums. If modifications are detected:

| Field | Type | Description |
|-------|------|-------------|
| `Table` | String | The table that was modified: `"SDT"` or `"SDTShadow"` |

## Example Output

### JSON Format

Real-time write access detection:
```json
{"Plugin":"ssdtmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":456,"TID":1234,"UserId":0,"ProcessName":"malware.exe","Method":null,"EventUID":"0x1234","TableIndex":74,"Table":"SSDT"}
```

SSDT Shadow write access:
```json
{"Plugin":"ssdtmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":456,"TID":1234,"UserId":0,"ProcessName":"malware.exe","Method":null,"EventUID":"0x1234","TableIndex":1024,"Table":"SSDTShadow"}
```

Integrity check failure on stop (SDT modified):
```json
{"Plugin":"ssdtmon","Table":"SDT"}
```

Integrity check failure on stop (SDT Shadow modified):
```json
{"Plugin":"ssdtmon","Table":"SDTShadow"}
```

## Detection Mechanism

1. **Memory Access Monitoring**: The plugin sets up memory write traps on the physical pages containing the SSDT and SSDT Shadow tables. Any write attempt triggers an event.

2. **Integrity Verification**: At plugin initialization, SHA-256 checksums are computed for the SDT and SDT Shadow structures. When DRAKVUF stops, these checksums are recalculated and compared. Mismatches indicate table modifications occurred.

## Technical Details

- The plugin reads `KiServiceTable` and `KiServiceLimit` from the kernel to locate the SSDT.
- For SSDT Shadow monitoring, it locates `win32k.sys` in the loaded module list and reads `W32pServiceTable` and `W32pServiceLimit`.
- Memory access traps are set at the page frame level (4KB granularity).
- The plugin uses the explorer.exe process context to translate win32k.sys addresses, as this driver is only mapped in GUI processes.
