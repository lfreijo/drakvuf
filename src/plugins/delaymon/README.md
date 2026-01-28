# Delaymon Plugin

## Overview

The delaymon plugin monitors calls to `NtDelayExecution`, the Windows NT kernel function that implements thread sleep operations. When a process calls `Sleep()`, `SleepEx()`, or similar delay functions in user mode, they ultimately invoke `NtDelayExecution` in the kernel. This plugin intercepts these calls and logs the requested delay interval.

This plugin is useful for:
- Detecting anti-analysis timing techniques used by malware (e.g., long sleeps to evade sandbox timeouts)
- Monitoring process behavior and timing patterns
- Identifying potential evasion attempts where malware uses delays to avoid detection

## Supported Operating Systems

| OS      | Supported |
|---------|-----------|
| Windows | Yes       |
| Linux   | No        |

The plugin hooks `NtDelayExecution` in `ntoskrnl.exe`, which is Windows-specific. The trap is configured with PID 4 (the Windows System process) to intercept kernel-level calls.

## Configuration Options

The delaymon plugin does not have any additional configuration options beyond the global output format setting. It automatically registers a breakpoint on `NtDelayExecution` when enabled.

## How to Enable the Plugin

The plugin is enabled by default. To control its compilation, use the meson build option:

```bash
# Enable the plugin (default)
meson configure -Dplugin-delaymon=true

# Disable the plugin
meson configure -Dplugin-delaymon=false
```

To explicitly disable the plugin at runtime:

```bash
drakvuf -r <kernel_profile.json> -d <domain> -x delaymon
```

To explicitly enable the plugin at runtime:

```bash
drakvuf -r <kernel_profile.json> -d <domain> -a delaymon
```

## Output Format

The plugin outputs events with the following fields:

### Standard Fields (from DRAKVUF common output)

| Field       | Description                                          |
|-------------|------------------------------------------------------|
| TimeStamp   | Timestamp of the event (seconds.microseconds)        |
| PID         | Process ID                                           |
| PPID        | Parent Process ID                                    |
| TID         | Thread ID                                            |
| UserId      | User ID of the process owner                         |
| ProcessName | Name of the process that called NtDelayExecution     |
| Method      | The hooked function name (NtDelayExecution)          |
| EventUID    | Unique identifier for the event                      |

### Plugin-Specific Fields

| Field           | Type    | Description                                                           |
|-----------------|---------|-----------------------------------------------------------------------|
| VCPU            | Numeric | Virtual CPU number where the call occurred                            |
| CR3             | Numeric | Control Register 3 value (page directory base address)                |
| DelayIntervalMs | Float   | Requested delay interval in milliseconds (converted from 100ns units) |

### Notes on DelayIntervalMs

- The native Windows delay interval is specified in 100-nanosecond units
- Negative values indicate relative delays (most common)
- The plugin converts the value to milliseconds for readability
- Large values (e.g., several minutes or hours) may indicate anti-sandbox techniques

## Example Output

### JSON Format (`-o json`)

```json
{
  "Plugin": "delaymon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 456,
  "TID": 5678,
  "UserId": 0,
  "ProcessName": "malware.exe",
  "Method": "NtDelayExecution",
  "EventUID": "0x1a2b3c",
  "VCPU": 0,
  "CR3": 7507968,
  "DelayIntervalMs": 5000.000000
}
```

### Key-Value Format (`-o kv`)

```
delaymon TIME:1234567890.123456 VCPU:0 CR3:7507968 ProcessName:malware.exe PID:1234 PPID:456 TID:5678 UserId:0 Method:NtDelayExecution DelayIntervalMs:5000.000000
```

### CSV Format (`-o csv`)

```
delaymon,1234567890.123456,1234,456,5678,0,malware.exe,NtDelayExecution,0x1a2b3c,0,7507968,5000.000000
```

## Use Cases

1. **Sandbox Evasion Detection**: Malware often uses long sleep intervals to outlast sandbox analysis timeouts. Monitoring `NtDelayExecution` helps identify samples attempting this technique.

2. **Timing-Based Anti-Analysis**: Some malware measures execution time before and after sleep calls to detect debugging or virtualization. This plugin helps track such behavior.

3. **Behavioral Analysis**: Understanding the timing patterns of a process can reveal its operational logic and help classify its behavior.

4. **Acceleration Techniques**: When combined with the ability to skip or reduce delays, this plugin enables faster analysis by identifying opportunities to accelerate malware execution.
