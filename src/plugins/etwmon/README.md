# etwmon Plugin

## Overview

The **etwmon** plugin monitors Event Tracing for Windows (ETW) infrastructure for modifications that may indicate tampering or evasion techniques. ETW is a Windows kernel-level tracing facility used for logging events from both kernel-mode and user-mode components. Attackers often target ETW to disable or manipulate logging to evade detection.

The plugin works by taking a snapshot of critical ETW structures at initialization, then comparing against the current state when DRAKVUF stops. This approach has zero runtime performance impact since checks are only performed at the end of analysis.

### What It Monitors

- **ETW Loggers (`_WMI_LOGGER_CONTEXT`)**: Monitors the `GetCpuClock` function pointer (used in the "infinity hook" technique) and `CallbackContext` for tampering
- **ETW Providers (`_ETW_GUID_ENTRY`)**: Tracks provider enable states and registered callbacks
- **Global ETW Handles**: Monitors kernel symbols like `EtwpPsProvRegHandle`, `EtwKernelProvRegHandle`, `EtwpNetProvRegHandle`, and others
- **Global ETW Callbacks**: Monitors callback arrays like `EtwpDiskIoNotifyRoutines` and `EtwpFileIoNotifyRoutines`
- **Active System Loggers**: Tracks changes to the `EtwpActiveSystemLoggers` count

## Supported Operating Systems

**Windows only** - The plugin supports:

- Windows 7 x64
- Windows 10 x64 (build 14393 / version 1607 and later)

**Note**: 32-bit (x86) Windows is not supported.

## Configuration Options

The etwmon plugin does not have specific configuration options beyond enabling/disabling it at build time.

## How to Enable the Plugin

The plugin is enabled by default. To explicitly control it during the build process:

### Using Meson

```bash
# Enable the plugin (default)
meson setup builddir -Dplugin-etwmon=true

# Disable the plugin
meson setup builddir -Dplugin-etwmon=false
```

When enabled, the build system sets `ENABLE_PLUGIN_ETWMON=1` in the configuration.

## Output Format

The plugin outputs events using DRAKVUF's standard output formatting system. Each event includes the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `Type` | String | Category of the monitored item. One of: `GetCpuClock`, `CallbackContext`, `Provider`, `RegCallback`, `GlobalCallback`, `GlobalHandle`, `SystemLoggerSettings` |
| `Name` | String | Identifier for the specific item. For loggers, this is the logger name (e.g., "Circular Kernel Context Logger"). For providers, this is the GUID in standard format (e.g., `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`). For global items, this is `Anonymous` or `ActiveSystemLoggers`. |
| `Action` | String | The type of change detected. Currently always `Modified` |
| `Value` | Hex | The new (current) value of the modified item |
| `PreviousValue` | Hex | The original value before modification |

### Detection Types

| Type | Description |
|------|-------------|
| `GetCpuClock` | Logger's CPU clock function pointer was modified (infinity hook detection) |
| `CallbackContext` | Logger's callback context was modified |
| `Provider` | Provider's enable info (level or enabled state) was modified |
| `RegCallback` | Provider's registered callback was modified |
| `GlobalCallback` | A global ETW callback pointer was modified |
| `GlobalHandle` | A global ETW handle was modified |
| `SystemLoggerSettings` | The active system loggers count was modified |

## Example Output

Example output in default format showing detected ETW modifications:

```
etwmon Type=GetCpuClock Name="Circular Kernel Context Logger" Action=Modified Value=0xfffff80012345678 PreviousValue=0xfffff80011111111
```

```
etwmon Type=Provider Name="{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}" Action=Modified Value=0x0 PreviousValue=0x0
```

```
etwmon Type=RegCallback Name="{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}" Action=Modified Value=0xfffff80087654321 PreviousValue=0xfffff80012345678
```

```
etwmon Type=GlobalCallback Name=Anonymous Action=Modified Value=0x0 PreviousValue=0xfffff80012340000
```

```
etwmon Type=GlobalHandle Name=Anonymous Action=Modified Value=0x0 PreviousValue=0xfffff80099999999
```

```
etwmon Type=SystemLoggerSettings Name=ActiveSystemLoggers Action=Modified Value=0x5 PreviousValue=0x8
```

## Monitored Global Symbols

### Windows 10

**Handles:**
- `EtwpEventTracingProvRegHandle`
- `EtwKernelProvRegHandle`
- `EtwpPsProvRegHandle`
- `EtwpNetProvRegHandle`
- `EtwpFileProvRegHandle`
- `EtwpRegTraceHandle`
- `EtwpMemoryProvRegHandle`
- `EtwAppCompatProvRegHandle`
- `EtwApiCallsProvRegHandle`
- `EtwCVEAuditProvRegHandle`
- `EtwThreatIntProvRegHandle`
- `EtwLpacProvRegHandle`
- `EtwAdminlessProvRegHandle`
- `EtwSecurityMitigationsRegHandle`
- `KiIntSteerEtwHandle`
- `HvlGlobalSystemEventsHandle`
- `PopDiagSleepStudyHandle`
- `WdipSemRegHandle`
- `IoTraceHandle`
- `IoMgrTraceHandle`
- `KitEtwHandle`
- `IopLiveDumpEtwRegHandle`
- `KseEtwHandle`
- `PopDiagHandle`
- `PopTriggerDiagHandle`
- `PpmEtwHandle`
- `PopBatteryEtwHandle`
- `PerfDiagGlobals`

**Callbacks:**
- `EtwpDiskIoNotifyRoutines` (2 entries)
- `EtwpFileIoNotifyRoutines` (4 entries)

### Windows 7

**Handles:**
- `EtwKernelProvRegHandle`
- `EtwPsProvRegHandle`
- `EtwNetProvRegHandle`
- `EtwDiskProvRegHandle`
- `EtwFileProvRegHandle`
- `EtwMemoryProvRegHandle`
- `g_EtwHandle`
- `g_AeLupSvcTriggerHandle`
- `TmpEtwHandle`
- `TmpTriggerHandle`
- `EtwpRegTraceHandle`
- `WdipSemRegHandle`
- `PpmEtwHandle`
- `PnpEtwHandle`
- `PopDiagHandle`
- `WheapEtwHandle`
- `PerfDiagGlobals`

**Callbacks:**
- `EtwpDiskIoNotifyRoutines` (4 entries)
- `RtlpSafeMachineFrameEntries` (8 entries)
- `EtwpFileIoNotifyRoutines` (4 entries)
- `EtwpSplitIoNotifyRoutines` (1 entry)
