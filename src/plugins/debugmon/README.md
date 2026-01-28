# Debugmon Plugin

## Overview

The debugmon plugin monitors debug events occurring within a virtual machine. It intercepts and logs various types of processor debug exceptions and interrupts, including hardware exceptions, software interrupts, NMIs (Non-Maskable Interrupts), and ICEBP (INT1) instructions.

This plugin is useful for:
- Detecting anti-debugging techniques used by malware
- Monitoring debug-related activity within guest VMs
- Tracking software breakpoint usage and exception handling

## Supported Operating Systems

The debugmon plugin operates at the hypervisor level and monitors low-level debug events. It is **OS-agnostic** and works with both:
- Windows
- Linux

The plugin intercepts debug traps directly from the hypervisor, making it independent of the guest operating system.

## Configuration Options

The debugmon plugin does not have any additional configuration options beyond the global output format setting. It automatically registers a DEBUG trap handler when enabled.

## How to Enable the Plugin

The plugin is enabled by default. To control its compilation, use the meson build option:

```bash
# Enable the plugin (default)
meson configure -Dplugin-debugmon=true

# Disable the plugin
meson configure -Dplugin-debugmon=false
```

## Output Format

The plugin outputs events with the following fields:

### Standard Fields (from DRAKVUF common output)

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | Control Register 3 value (page directory base) |
| Process Name | Name of the process that triggered the event |
| UID/SessionID | User ID (Linux) or Session ID (Windows) |
| PID | Process ID |
| PPID | Parent Process ID |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| VCPU | Virtual CPU number (also included in plugin output) |
| CR3 | CR3 register value in hexadecimal |
| RIP | Instruction pointer at the time of the debug event (hexadecimal) |
| DebugType | Numeric type of the debug event (0-6) |
| DebugTypeStr | Human-readable description of the debug event type |

### Debug Event Types

| Value | DebugTypeStr | Description |
|-------|--------------|-------------|
| 0 | external interrupt | External hardware interrupt |
| 2 | nmi | Non-Maskable Interrupt |
| 3 | hardware exception | Hardware-generated exception (e.g., INT3 breakpoint) |
| 4 | software interrupt | Software interrupt instruction (INT n) |
| 5 | ICEBP | In-Circuit Emulator Breakpoint (INT1, opcode 0xF1) |
| 6 | software exception | Software-generated exception |

## Example Output

### Default Format
```
[DEBUGMON] TIME:1234567890.123456 VCPU:0 CR3:0x1AA000 "explorer.exe": UID:0 PID:1234 PPID:456 VCPU:0 CR3:0x1AA000 RIP:0x7FFE0000 DebugType:3 DebugTypeStr:"hardware exception"
```

### JSON Format
```json
{
  "Plugin": "debugmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1AA000",
  "ProcessName": "explorer.exe",
  "UID": 0,
  "PID": 1234,
  "PPID": 456,
  "RIP": "0x7FFE0000",
  "DebugType": 3,
  "DebugTypeStr": "hardware exception"
}
```

### CSV Format
```
debugmon,1234567890.123456,0,0x1AA000,explorer.exe,0,1234,456,0,0x1AA000,0x7FFE0000,3,"hardware exception"
```

### KV (Key-Value) Format
```
DEBUGMON TIME=1234567890.123456 VCPU=0 CR3=0x1AA000 ProcessName="explorer.exe" UID=0 PID=1234 PPID=456 RIP=0x7FFE0000 DebugType=3 DebugTypeStr="hardware exception"
```
