# Callbackmon Plugin

## Overview

The callbackmon plugin monitors Windows kernel callback mechanisms for modifications during analysis. It captures a snapshot of registered callbacks at the start of analysis, tracks driver loading/unloading during execution, and compares against a final snapshot when DRAKVUF stops. Any changes to kernel callbacks (added, removed, or replaced) are reported, making this plugin useful for detecting rootkits and other malware that manipulate kernel callback tables to hide their presence or intercept system events.

## Supported Operating Systems

**Windows only** - This plugin is specifically designed for Windows kernel callback structures.

Supported Windows versions:
- Windows Vista (build 6000) and Vista SP1/SP2 (builds 6001, 6002)
- Windows 7 SP1 (build 7601)
- Windows 8.1 (build 9600)
- Windows 10 RS1 (build 14393) and later
- Windows 10 1803 (build 17134) - required for WFP callouts and NDIS monitoring

Note: Object type callback monitoring is only available on 64-bit systems.

## Configuration Options

The plugin accepts two optional JSON profile paths for extended monitoring:

| Option | Description |
|--------|-------------|
| `--json-netio <path>` | JSON profile for netio.sys (enables WFP callout monitoring) |
| `--json-ndis <path>` | JSON profile for ndis.sys (enables NDIS protocol callback monitoring) |

These profiles are only effective on Windows 7 SP1 (build 7601) and Windows 10 1803 (build 17134).

## How to Enable the Plugin

The plugin is enabled by default in the build system. To explicitly control it during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-callbackmon=true

# Disable the plugin
meson setup build -Dplugin-callbackmon=false
```

At runtime, no special flags are needed to enable the plugin. The optional JSON profiles can be specified:

```bash
drakvuf -r /path/to/kernel.json -d domain_name \
    --json-netio /path/to/netio.json \
    --json-ndis /path/to/ndis.json
```

## Monitored Callback Lists

The plugin monitors the following kernel callback structures:

### Process/Thread/Image Notifications
- `PspCreateProcessNotifyRoutine` - Process creation/termination callbacks
- `PspCreateThreadNotifyRoutine` - Thread creation/termination callbacks
- `PspLoadImageNotifyRoutine` - Image (DLL/driver) load callbacks

### System Event Callbacks
- `KeBugCheckCallbackListHead` - Bug check (BSOD) callbacks
- `KeBugCheckReasonCallbackListHead` - Bug check reason callbacks
- `PopRegisteredPowerSettingCallbacks` - Power setting change callbacks
- `IopNotifyShutdownQueueHead` - System shutdown callbacks
- `IopNotifyLastChanceShutdownQueueHead` - Last-chance shutdown callbacks

### Registry and Filesystem Callbacks
- `CallbackListHead` - Registry operation callbacks
- `SeFileSystemNotifyRoutinesHead` - Logon session termination callbacks
- `IopFsNotifyChangeQueueHead` - Filesystem change notification callbacks

### Driver Callbacks
- `IopDriverReinitializeQueueHead` - Driver reinitialization callbacks
- `IopBootDriverReinitializeQueueHead` - Boot driver reinitialization callbacks
- `IopUpdatePriorityCallbackRoutine` - I/O priority update callbacks (not available on Vista)

### System/Hardware Callbacks
- `KiNmiCallbackListHead` - Non-maskable interrupt (NMI) callbacks
- `RtlpDebugPrintCallbackList` - Debug print callbacks
- `EmpCallbackListHead` - Errata manager callbacks

### Plug and Play Callbacks
- `PnpProfileNotifyList` - PnP profile notification callbacks
- `PnpDeviceClassNotifyList` - PnP device class notification callbacks

### Win32 Subsystem Callouts
- `PsWin32CallBack` (Windows 8.1+) or individual callout symbols (pre-8.1):
  - `PspW32ProcessCallout`
  - `PspW32ThreadCallout`
  - `ExGlobalAtomTableCallout`
  - `KeGdiFlushUserBatch`
  - `PopEventCallout`
  - `PopStateCallout`
  - `PopWin32InfoCallout`
  - `PspW32JobCallout`
  - `ExDesktopOpenProcedureCallout`
  - `ExDesktopOkToCloseProcedureCallout`
  - `ExDesktopCloseProcedureCallout`
  - `ExDesktopDeleteProcedureCallout`
  - `ExWindowStationOkToCloseProcedureCallout`
  - `ExWindowStationCloseProcedureCallout`
  - `ExWindowStationDeleteProcedureCallout`
  - `ExWindowStationParseProcedureCallout`
  - `ExWindowStationOpenProcedureCallout`
  - `ExLicensingWin32Callout`

### Windows Filtering Platform (WFP) Callouts
- `gWfpGlobal` callbacks in netio.sys (requires `--json-netio` profile)

### NDIS Protocol Callbacks (requires `--json-ndis` profile)
- Protocol block handlers (send, receive, status, etc.)
- Miniport block handlers (interrupt, packet indication, etc.)

### Object Manager Callbacks
- Callback objects registered in the `\Callback` object directory
- Object type callbacks (pre/post operation callbacks)
- Object type initializer procedures (Dump, Open, Close, Delete, Parse, Security, QueryName, OkayToClose)

## Output Format

The plugin outputs events when callbacks are detected as changed at the end of analysis. Each event includes:

| Field | Description |
|-------|-------------|
| `Type` | Always "Callback" |
| `ListName` | Name of the callback list that was modified (e.g., "ProcessNotify", "Registry") |
| `Module` | Full path of the driver module containing the callback, or "\<Unknown\>" if not found |
| `RVA` | Relative Virtual Address of the callback within its module (0 if module unknown) |
| `Action` | Type of change: "Added", "Removed", "Replaced", or "Modified" |

## Example Output

### JSON Format
```json
{"Plugin": "callbackmon", "Type": "Callback", "ListName": "ProcessNotify", "Module": "\\SystemRoot\\System32\\drivers\\malware.sys", "RVA": "0x1234", "Action": "Added"}
```

```json
{"Plugin": "callbackmon", "Type": "Callback", "ListName": "Registry", "Module": "\\SystemRoot\\System32\\drivers\\suspicious.sys", "RVA": "0x5678", "Action": "Removed"}
```

```json
{"Plugin": "callbackmon", "Type": "Callback", "ListName": "PspW32ProcessCallout", "Module": "\\SystemRoot\\System32\\win32k.sys", "RVA": "0xabcd", "Action": "Replaced"}
```

### Key-Value Format
```
callbackmon Type=Callback ListName=ProcessNotify Module=\SystemRoot\System32\drivers\malware.sys RVA=0x1234 Action=Added
```

## Action Types

| Action | Meaning |
|--------|---------|
| `Added` | A new callback was registered in the list |
| `Removed` | An existing callback was unregistered from the list |
| `Replaced` | A callout function pointer was changed to a different address (Win32 callouts) |
| `Modified` | An NDIS protocol/miniport handler was changed |

## Use Cases

1. **Rootkit Detection**: Detect when malware registers process/thread notification callbacks to hide processes or inject code
2. **Security Monitoring**: Identify unauthorized registry callbacks that could be used to hide registry modifications
3. **Driver Analysis**: Track which callbacks a driver registers and whether it properly unregisters them
4. **Malware Analysis**: Observe callback manipulation techniques used by advanced threats
