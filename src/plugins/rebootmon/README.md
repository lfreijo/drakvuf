# Rebootmon Plugin

## Overview

The rebootmon plugin monitors system reboot and power-off related events in virtual machines. It hooks into kernel-level reboot and shutdown functions to detect when a guest operating system attempts to restart, halt, or power off the system.

This plugin is useful for:
- Detecting when malware attempts to force a system reboot
- Monitoring shutdown/reboot behavior during malware analysis
- Optionally aborting DRAKVUF analysis when power-off events occur

## Supported Operating Systems

**Linux only** - This plugin currently supports only Linux guest operating systems. Windows guests are explicitly not supported; attempting to use this plugin on a Windows guest will cause an initialization error.

## Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `abort_on_power_off` | boolean | When set to `true`, DRAKVUF will abort analysis (with `SIGDRAKVUFPOWEROFF`) when any of the following events are detected: `machine_restart`, `machine_halt`, `machine_power_off`, or `machine_emergency_restart`. |

## How to Enable the Plugin

The plugin is enabled by default in the meson build system.

To explicitly enable or disable during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-rebootmon=true

# Disable the plugin
meson setup build -Dplugin-rebootmon=false
```

## Hooked Functions

The plugin hooks the following kernel functions:

| Hook Target | Kernel Function | Description |
|-------------|-----------------|-------------|
| `sys_reboot` | `__do_sys_reboot` | The reboot system call handler |
| `machine_restart` | `machine_restart` | Kernel function to restart the machine |
| `machine_halt` | `machine_halt` | Kernel function to halt the machine |
| `machine_power_off` | `machine_power_off` | Kernel function to power off the machine |
| `machine_emergency_restart` | `machine_emergency_restart` | Kernel function for emergency restart |

## Output Format

### Standard Fields (present in all output)

| Field | Description |
|-------|-------------|
| `Plugin` | Always "rebootmon" |
| `TimeStamp` | Timestamp of the event |
| `PID` | Process ID that triggered the event |
| `PPID` | Parent process ID |
| `TID` | Thread ID |
| `UserId` | User ID |
| `ProcessName` | Name of the process that triggered the event |
| `Method` | The hooked function name (e.g., "sys_reboot", "machine_restart") |
| `EventUID` | Unique event identifier |

### Event-Specific Fields

#### sys_reboot

| Field | Description |
|-------|-------------|
| `Magic1` | First magic number for reboot syscall validation |
| `Magic2` | Second magic number for reboot syscall validation |
| `Cmd` | Reboot command being requested |
| `Arg` | Optional argument string (used with `LINUX_REBOOT_CMD_RESTART2`) |

**Magic Number Values:**
- `LINUX_REBOOT_MAGIC1` (0xfee1dead)
- `LINUX_REBOOT_MAGIC2` (672274793)
- `LINUX_REBOOT_MAGIC2A` (85072278)
- `LINUX_REBOOT_MAGIC2B` (369367448)
- `LINUX_REBOOT_MAGIC2C` (537993216)

**Reboot Command Values:**
- `LINUX_REBOOT_CMD_RESTART` (0x01234567) - Restart system using default command
- `LINUX_REBOOT_CMD_HALT` (0xCDEF0123) - Stop OS and give control to ROM monitor
- `LINUX_REBOOT_CMD_CAD_ON` (0x89ABCDEF) - Ctrl-Alt-Del triggers RESTART
- `LINUX_REBOOT_CMD_CAD_OFF` (0x00000000) - Ctrl-Alt-Del sends SIGINT to init
- `LINUX_REBOOT_CMD_POWER_OFF` (0x4321FEDC) - Stop OS and remove all power
- `LINUX_REBOOT_CMD_RESTART2` (0xA1B2C3D4) - Restart with given command string
- `LINUX_REBOOT_CMD_SW_SUSPEND` (0xD000FCE2) - Suspend using software suspend
- `LINUX_REBOOT_CMD_KEXEC` (0x45584543) - Restart using previously loaded kernel

#### machine_restart

| Field | Description |
|-------|-------------|
| `Cmd` | Command string passed to the restart function (may be empty) |

#### machine_halt / machine_power_off / machine_emergency_restart

No additional fields beyond the standard fields.

## Example Output

### JSON Format

**sys_reboot event:**
```json
{"Plugin":"rebootmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":1,"TID":1234,"UserId":0,"ProcessName":"shutdown","Method":"sys_reboot","EventUID":"0x1234","Magic1":"LINUX_REBOOT_MAGIC1","Magic2":"LINUX_REBOOT_MAGIC2","Cmd":"LINUX_REBOOT_CMD_POWER_OFF","Arg":null}
```

**machine_restart event:**
```json
{"Plugin":"rebootmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":1,"TID":1234,"UserId":0,"ProcessName":"reboot","Method":"machine_restart","EventUID":"0x1234","Cmd":""}
```

**machine_power_off event:**
```json
{"Plugin":"rebootmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":1,"TID":1234,"UserId":0,"ProcessName":"poweroff","Method":"machine_power_off","EventUID":"0x1234"}
```
