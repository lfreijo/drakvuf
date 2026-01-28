# Rootkitmon Plugin

## Overview

The rootkitmon plugin detects various kernel-level rootkit techniques in Windows virtual machines. It monitors critical kernel structures and registers for unauthorized modifications that are commonly used by rootkits to hide their presence or escalate privileges.

The plugin performs both real-time monitoring (via hooks and traps) and integrity verification (comparing checksums at startup vs shutdown).

### Monitored Components

| Component | Detection Method |
|-----------|------------------|
| **IDT (Interrupt Descriptor Table)** | SHA256 checksum comparison |
| **GDT (Global Descriptor Table)** | Entry enumeration and comparison |
| **IDTR/GDTR registers** | Value comparison across sessions |
| **MSR_LSTAR register** | Real-time MSR write monitoring |
| **CR4 register** | Real-time register write monitoring (SMEP/SMAP) |
| **Driver code sections** | SHA256 checksum of non-paged, non-writable sections |
| **Driver objects** | Dispatch table and FastIO checksum verification |
| **Device stacks** | AttachedDevice chain integrity |
| **HalPrivateDispatchTable** | Memory write monitoring |
| **g_CiEnabled / g_CiCallbacks** | Code integrity flag and callback table monitoring |
| **WFP callouts** | FwpmCalloutAdd0 function hook |
| **Filesystem filter callbacks** | Volume callback enumeration and comparison |

## Supported Operating Systems

**Windows Only** - This plugin monitors Windows-specific kernel structures and is not supported on Linux.

| Windows Version | Support |
|-----------------|---------|
| Windows Vista RTM | Partial (CI checks limited) |
| Windows 7 SP1 | Full support |
| Windows 8+ | Full support (requires ci.dll profile for CI checks) |

## Configuration Options

| Option | Command-Line Flag | Description |
|--------|-------------------|-------------|
| `fwpkclnt_profile` | `--json-fwpkclnt` | JSON profile for fwpkclnt.sys (enables WFP callout monitoring) |
| `fltmgr_profile` | `--json-fltmgr` | JSON profile for fltmgr.sys (enables filesystem filter callback monitoring) |
| `ci_profile` | `--json-ci` | JSON profile for ci.dll (required for CI checks on Windows 8.1+) |

All profiles are optional but recommended for complete coverage.

## How to Enable the Plugin

The plugin is enabled by default. To explicitly control it during the build:

```bash
# Enable (default)
meson setup build -Dplugin-rootkitmon=true

# Disable
meson setup build -Dplugin-rootkitmon=false
```

### Runtime Usage

```bash
# Basic usage
drakvuf -r /path/to/kernel.json -d <domain>

# With all profiles for maximum coverage
drakvuf -r /path/to/kernel.json -d <domain> \
    --json-fwpkclnt /path/to/fwpkclnt.json \
    --json-fltmgr /path/to/fltmgr.json \
    --json-ci /path/to/ci.json
```

## Output Format

The plugin outputs events with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `Type` | String | Category of the detection (see table below) |
| `Action` | String | What happened: `Modified`, `Called`, or `Disabled` |
| `Name` | String | Name of the affected component (optional) |
| `Value` | Hex | Current value (optional) |
| `PreviousValue` | Hex | Previous value before modification (optional) |
| `Module` | String | Driver module name (optional) |

### Detection Types

| Type | Description |
|------|-------------|
| `SystemRegister` | CPU register modification (IDTR, GDTR, LSTAR) |
| `SystemStruct` | Kernel structure modification (IDT, GDT, HalPrivateDispatchTable, g_CiEnabled, g_CiCallbacks, VolumeFilterCallbacks) |
| `DriverCRC` | Driver code section checksum mismatch |
| `DriverObject` | Driver dispatch table or FastIO modification |
| `DriverStack` | Device stack (AttachedDevice chain) modification |
| `Function` | Suspicious function called (FwpmCalloutAdd0) |
| `SecurityFeature` | Security feature disabled (CR4.SMEP, CR4.SMAP, EFLAGS.SMAP) |

## Example Output

### JSON Format

#### MSR_LSTAR Modification
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "SystemRegister",
  "Action": "Modified",
  "Name": "LSTAR",
  "Value": "0xfffff80012345678",
  "PreviousValue": "0xfffff80011111111",
  "Module": "\\SystemRoot\\system32\\drivers\\malware.sys"
}
```

#### Driver Code Integrity Violation
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "DriverCRC",
  "Action": "Modified",
  "Module": "\\SystemRoot\\system32\\drivers\\ntfs.sys"
}
```

#### IDT Modification
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "SystemStruct",
  "Action": "Modified",
  "Name": "IDT"
}
```

#### SMEP/SMAP Bypass Detection
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "SecurityFeature",
  "Action": "Disabled",
  "Name": "CR4.SMEP"
}
```

#### WFP Callout Registration
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "Function",
  "Action": "Called",
  "Name": "FwpmCalloutAdd0"
}
```

#### Code Integrity Tampering
```json
{
  "Plugin": "rootkitmon",
  "TimeStamp": "1699900000.000000",
  "Type": "SystemStruct",
  "Action": "Modified",
  "Name": "g_CiEnabled"
}
```

## Detection Mechanisms

### Real-Time Monitoring

The plugin sets up the following real-time traps:

1. **MSR Write Hook** - Monitors writes to MSR_LSTAR (syscall entry point)
2. **CR4 Write Hook** - Monitors CR4 register changes (SMEP/SMAP bits)
3. **Memory Access Hook** - Monitors writes to HalPrivateDispatchTable
4. **Syscall Hooks** - Monitors SeValidateImageHeader and SeValidateImageData for CI checks
5. **Function Hook** - Monitors FwpmCalloutAdd0 for WFP callout registration

### Integrity Verification (on plugin stop)

When DRAKVUF stops, the plugin performs final integrity checks:

1. **Driver Code Sections** - Recalculates SHA256 checksums of all non-paged, non-writable driver sections
2. **Driver Objects** - Verifies dispatch tables and FastIO dispatch structures
3. **Device Stacks** - Checks AttachedDevice chains for modifications
4. **Descriptors** - Compares IDT/GDT checksums and register values
5. **Code Integrity** - Verifies g_CiEnabled and g_CiCallbacks
6. **Filter Callbacks** - Compares filesystem filter callback registrations

## Technical Notes

- The plugin calculates SHA256 checksums for integrity verification using GLib's checksum API
- Driver section checksums only include sections with `MEM_NOT_PAGED` and without `MEM_WRITE` flags
- The CI callback table size varies by Windows version (3 entries for Vista/Win7, 30 for Win8+)
- PatchGuard may legitimately modify LSTAR temporarily; the plugin filters these false positives
- 32-bit Windows guests have limited support (driver object checks are skipped)
