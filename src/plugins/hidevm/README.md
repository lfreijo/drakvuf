# HideVM Plugin

## Overview

The HideVM plugin is an anti-detection plugin that helps hide the presence of a virtual machine from guest operating system processes. It works by intercepting and spoofing responses to common VM detection queries that malware and other software use to determine if they are running inside a virtualized environment.

The plugin implements two main VM-hiding techniques:

1. **MSAcpi_ThermalZoneTemperature Spoofing**: Intercepts WMI queries for thermal zone information via the `NtDeviceIoControlFile` syscall. When `WmiPrvSE.exe` queries the `MSAcpi_ThermalZoneTemperature` WMI class (GUID: `A1BC18C0-A7C8-11D1-BF3C-00A0C9062910`), the plugin returns fake thermal data to make the system appear like physical hardware.

2. **WQL Performance Query Spoofing**: Hooks the `IWbemServices::ExecQuery` method in `fastprox.dll` to intercept WQL queries for performance-related WMI classes. Queries targeting `Win32_PerfFormattedData*` or `Win32_PerfRawData*` classes are replaced with queries for `Win32_BIOS`, which returns non-VM-specific information.

3. **Boot Time Advancement**: Optionally advances the system boot time (tick count) to make the system appear to have been running longer, defeating timing-based VM detection.

## Supported Operating Systems

**Windows Only**

The plugin supports the following Windows versions:
- Windows 7 (x86 and x64)
- Windows 10 (x86 and x64)

Linux is **not supported** by this plugin.

**Note**: WQL query spoofing for `Win32_PerfFormattedData*` and `Win32_PerfRawData*` classes requires usermode hooking support and is only available on Windows 7 and Windows 10. The thermal zone spoofing works on other Windows versions as well.

## Configuration Options

The plugin accepts one configuration option:

| Option | Type | Description |
|--------|------|-------------|
| `hidevm_delay` | uint64 | Number of seconds to advance the system boot time (tick count). Set to 0 to disable boot time advancement. |

The delay value is converted to tick counts and written to `KUSER_SHARED_DATA.TickCount` to make the system appear to have been running for a longer period.

## How to Enable the Plugin

### Meson Build System

The plugin is enabled by default. To explicitly control it:

```bash
# Enable (default)
meson setup build -Dplugin-hidevm=true

# Disable
meson setup build -Dplugin-hidevm=false
```

### Autotools Build System

```bash
# Enable (default)
./configure --enable-plugin-hidevm

# Disable
./configure --disable-plugin-hidevm
```

### Runtime Configuration

When running DRAKVUF, use the `--hidevm-delay` option to specify the boot time advancement in seconds:

```bash
drakvuf --hidevm-delay 3600  # Advance boot time by 1 hour
```

## Output Format

The plugin produces output when it successfully spoofs a VM detection query. Output includes standard DRAKVUF fields plus plugin-specific fields.

### Standard Fields

| Field | Description |
|-------|-------------|
| `Time` | Timestamp of the event (seconds.microseconds) |
| `PID` | Process ID of the process that triggered the event |
| `PPID` | Parent Process ID |
| `TID` | Thread ID |
| `ProcessName` | Name of the process |
| `Method` | The hooked function name (if applicable) |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| `Reason` | Description of what was spoofed |
| `strQuery` | The original WQL query string (only for WMI query spoofing events) |

### Reason Values

- `"MSAcpi_ThermalZoneTemperature query spoofed"` - Thermal zone WMI query was intercepted and fake data was returned
- `"WMI query spoofed"` - A WQL query for performance data classes was redirected to Win32_BIOS

## Example Output

### Thermal Zone Spoofing (KV format)

```
hidevm Time=1234567890.123456,PID=1234,PPID=456,TID=5678,ProcessName="WmiPrvSE.exe",Reason="MSAcpi_ThermalZoneTemperature query spoofed"
```

### WQL Query Spoofing (KV format)

```
hidevm Time=1234567890.123456,PID=2468,PPID=789,TID=1357,ProcessName="malware.exe",Reason="WMI query spoofed",strQuery="select * from win32_perfformatteddata_perfos_processor"
```

### JSON Format Example

```json
{
  "Plugin": "hidevm",
  "Time": "1234567890.123456",
  "PID": 1234,
  "PPID": 456,
  "TID": 5678,
  "ProcessName": "WmiPrvSE.exe",
  "Reason": "MSAcpi_ThermalZoneTemperature query spoofed"
}
```

## Technical Details

### Thermal Zone Spoofing Stages

The plugin uses a multi-stage approach to intercept thermal zone queries:

1. **Stage 1 (IOCTL_WMI_OPEN_GUID_BLOCK)**: Intercepts the WMI GUID open request for the thermal zone GUID. Returns a fake handle (`0xFACEDEAD`) when `STATUS_WMI_GUID_NOT_FOUND` would normally be returned.

2. **Stage 2 (IOCTL_WMI_QUERY_GUID_INFORMATION)**: Validates the fake handle and returns success status for GUID information queries.

3. **Stage 3 (IOCTL_WMI_QUERY_ALL_DATA)**: Returns fabricated thermal zone data including fake temperature readings and ACPI thermal zone path information.

### Hooked Functions

- `NtDeviceIoControlFile` - Kernel syscall for device I/O control (thermal zone spoofing)
- `NtClose` - Handles cleanup of the fake WMI GUID handle
- `IWbemServices::ExecQuery` - COM method in `fastprox.dll` (WQL query spoofing)

### Usermode Hook Offsets

The plugin uses hardcoded offsets for `IWbemServices::ExecQuery` in `fastprox.dll`:

| Windows Version | Architecture | DLL Path | Offset |
|-----------------|--------------|----------|--------|
| Windows 7 | x64 | System32\wbem\fastprox.dll | 0x7100 |
| Windows 7 | x86 | SysWOW64\wbem\fastprox.dll | 0x1ebe0 |
| Windows 10 | x64 | System32\wbem\fastprox.dll | 0x2b280 |
| Windows 10 | x86 | SysWOW64\wbem\fastprox.dll | 0x30690 |
