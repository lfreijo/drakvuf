# DKOMMON Plugin

## Overview

The DKOMMON (Direct Kernel Object Manipulation Monitor) plugin detects rootkit-style hiding techniques used by malware to conceal processes, drivers, and Windows services from the operating system. It works by maintaining an internal list of known objects and comparing them against the system state when DRAKVUF stops, identifying any objects that have been unlinked or hidden from normal enumeration.

The plugin monitors the following types of hidden objects:

- **Hidden Processes**: Detects processes that have been unlinked from the `EPROCESS.ActiveProcessLinks` doubly-linked list (DKOM technique)
- **Hidden Drivers**: Detects drivers that have been removed from the `PsLoadedModuleList` kernel structure
- **Hidden Services**: Detects Windows services that have been removed from the services database in `services.exe`

## Supported Operating Systems

**Windows Only** - This plugin is designed exclusively for Windows guest VMs.

### Supported Windows Versions for Service Monitoring

Service hiding detection requires a JSON profile for `services.exe` and is only supported on:

- Windows 7 SP1 x64 (Build 7601)
- Windows 10 1803 x64 (Build 17134)

Process and driver hiding detection works on all Windows versions.

## Configuration Options

| Option | Description |
|--------|-------------|
| `--json-services <path>` | Path to the JSON profile for `services.exe`. Required for service hiding detection. |

## How to Enable the Plugin

### Meson Build Option

The plugin is enabled by default. To explicitly control it during configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-dkommon=true

# Disable the plugin
meson setup build -Dplugin-dkommon=false
```

### Runtime Usage

To enable service monitoring, provide the services.exe JSON profile:

```bash
drakvuf -r <rekall_profile> -d <domain> --json-services /path/to/services.json
```

## Output Format

The plugin outputs events using DRAKVUF's standard output format (default, CSV, KV, or JSON depending on the `-o` option).

### Output Fields

#### Hidden Process Detection

| Field | Description |
|-------|-------------|
| `Message` | Always "Hidden Process" |
| `HiddenPID` | The Process ID (PID) of the hidden process |

#### Hidden Driver Detection

| Field | Description |
|-------|-------------|
| `Message` | Always "Hidden Driver" |
| `DriverName` | The name of the hidden driver module |

#### Hidden Service Detection

| Field | Description |
|-------|-------------|
| `Message` | Always "Hidden Service" |
| `DriverName` | The name of the hidden service (or "\<Anonymous\>" if the name cannot be read) |

### Standard Fields

All output events also include standard DRAKVUF fields such as:
- Timestamp
- vCPU number
- Current process context (CR3, process name, PID, PPID)
- Thread ID
- User ID (if available)

## Example Output

### JSON Format (`-o json`)

**Hidden Process:**
```json
{"Plugin": "dkommon", "TimeStamp": "1234567890.123456", "Message": "Hidden Process", "HiddenPID": 4532}
```

**Hidden Driver:**
```json
{"Plugin": "dkommon", "TimeStamp": "1234567890.123456", "Message": "Hidden Driver", "DriverName": "malicious.sys"}
```

**Hidden Service:**
```json
{"Plugin": "dkommon", "TimeStamp": "1234567890.123456", "Message": "Hidden Service", "DriverName": "MaliciousService"}
```

### Default Format

**Hidden Process:**
```
[DKOMMON] TIME:1234567890.123456 VCPU:0 CR3:0x1aa000 dkommon Message="Hidden Process" HiddenPID=4532
```

**Hidden Driver:**
```
[DKOMMON] TIME:1234567890.123456 VCPU:0 CR3:0x1aa000 dkommon Message="Hidden Driver" DriverName="malicious.sys"
```

**Hidden Service:**
```
[DKOMMON] TIME:1234567890.123456 VCPU:0 CR3:0x1aa000 dkommon Message="Hidden Service" DriverName="MaliciousService"
```

## Detection Mechanism

### Process Hiding Detection

1. At startup, enumerates all processes via `drakvuf_enumerate_processes()`
2. Hooks `PspInsertProcess` to track new process creation
3. Hooks `PspProcessDelete` to track process termination
4. On process deletion, checks if `EPROCESS.ActiveProcessLinks.Flink` and `Blink` both point to the current entry (indicating unlinking)
5. On DRAKVUF stop, re-enumerates processes and compares against the tracked list

### Driver Hiding Detection

1. At startup, enumerates loaded drivers from `PsLoadedModuleList`
2. Hooks `MiProcessLoaderEntry` to track driver load/unload events
3. On DRAKVUF stop, re-enumerates drivers and compares against the tracked list

### Service Hiding Detection

1. Locates `services.exe` process and finds the `g_serviceDB` (Win7) or `g_ServicesDB` (Win10) pointer via pattern matching
2. Enumerates all service records from the services database linked list
3. Hooks service add/remove functions in `services.exe` to track changes
4. On DRAKVUF stop, re-enumerates services and compares against the tracked list

## Limitations

- Service monitoring requires a JSON profile generated for `services.exe` and only works on Windows 7 SP1 x64 and Windows 10 1803 x64
- The plugin operates on 64-bit Windows guests only for service monitoring
- Detection occurs primarily at DRAKVUF stop time; real-time hidden process detection occurs only during process termination
