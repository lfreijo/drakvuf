# BSODMON Plugin

## Overview

The bsodmon plugin monitors Windows Blue Screen of Death (BSOD) events by hooking the `KeBugCheck2` kernel function. When a BSOD occurs, the plugin captures detailed information about the crash including the bug check code, its human-readable name, and the four bug check parameters. Optionally, it can dump the entire system memory for post-mortem analysis.

This plugin is useful for:
- Detecting kernel panics and system crashes in monitored Windows virtual machines
- Capturing crash dump data for forensic analysis
- Automated malware analysis sandboxes to detect samples that cause system instability

## Supported Operating Systems

**Windows only** - This plugin hooks Windows-specific kernel functions (`KeBugCheck2`) and uses Windows bug check codes. It supports Windows 7 and later versions. The plugin contains a comprehensive mapping of bug check codes to their symbolic names based on the Microsoft bug check code reference.

Linux is not supported.

## Configuration Options

The plugin accepts the following configuration options at runtime:

| Option | Description |
|--------|-------------|
| `-b` | Exit DRAKVUF execution as soon as a BSOD is detected. When enabled, the plugin sends a `SIGDRAKVUFKERNELPANIC` signal to interrupt DRAKVUF. |
| `--bsodmon-ignore-stop` | Prevent bsodmon from stopping when other plugins stop. This allows the plugin to continue monitoring for BSODs even after other plugins have finished. |
| `--crashdump-dir <directory>` | Directory path where crash dump files will be stored. When specified, the plugin dumps the entire guest physical memory to `<directory>/crashdump.bin` and writes metadata to `<directory>/crashdump.metadata` in JSON format. |

## How to Enable the Plugin (Meson Option)

The plugin is enabled by default. To explicitly control it during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-bsodmon=true

# Disable the plugin
meson setup build -Dplugin-bsodmon=false
```

When enabled, the build system sets the `ENABLE_PLUGIN_BSODMON` preprocessor definition.

## Output Format

### Standard Output Fields

When a BSOD is detected, the plugin outputs the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `VCPU` | Integer | The virtual CPU number where the BSOD was triggered |
| `CR3` | Integer | The CR3 register value (page directory base) at the time of the crash |
| `BugCheckCode` | Hex | The Windows bug check code (e.g., `0x50`) |
| `BugCheckName` | String | Human-readable name of the bug check code (e.g., `PAGE_FAULT_IN_NONPAGED_AREA`). Shows `UNKNOWN_CODE` if the code is not in the known mapping. |
| `BugCheckParameter1` | Hex | First parameter of the bug check (meaning varies by bug check code) |
| `BugCheckParameter2` | Hex | Second parameter of the bug check |
| `BugCheckParameter3` | Hex | Third parameter of the bug check |
| `BugCheckParameter4` | Hex | Fourth parameter of the bug check |

Standard DRAKVUF output fields (timestamp, process info, etc.) are also included based on the global output format setting.

### Crash Dump Metadata File

When `--crashdump-dir` is specified, a `crashdump.metadata` JSON file is created with:

| Field | Description |
|-------|-------------|
| `KernelBase` | The kernel base address (hex string) |
| `BugCheckCode` | The bug check code (hex string) |
| `Param1` - `Param4` | Bug check parameters (hex strings) |
| `CR3` | CR3 register value (hex string) |
| `RSP` | Stack pointer value (hex string) |

## Example Output

### JSON Format

```json
{
  "Plugin": "bsodmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": 456789,
  "BugCheckCode": "0x50",
  "BugCheckName": "PAGE_FAULT_IN_NONPAGED_AREA",
  "BugCheckParameter1": "0xfffff80012345678",
  "BugCheckParameter2": "0x0",
  "BugCheckParameter3": "0xfffff80087654321",
  "BugCheckParameter4": "0x2"
}
```

### Key-Value Format

```
Plugin=bsodmon TimeStamp=1234567890.123456 VCPU=0 CR3=456789 BugCheckCode=0x50 BugCheckName="PAGE_FAULT_IN_NONPAGED_AREA" BugCheckParameter1=0xfffff80012345678 BugCheckParameter2=0x0 BugCheckParameter3=0xfffff80087654321 BugCheckParameter4=0x2
```

### Crash Dump Metadata Example

```json
{
  "KernelBase": "fffff80012340000",
  "BugCheckCode": "50",
  "Param1": "fffff80012345678",
  "Param2": "0",
  "Param3": "fffff80087654321",
  "Param4": "2",
  "CR3": "1a3000",
  "RSP": "fffff88012345670"
}
```

## Common Bug Check Codes

Some frequently encountered bug check codes that the plugin can identify:

| Code | Name |
|------|------|
| `0x0000000A` | `IRQL_NOT_LESS_OR_EQUAL` |
| `0x0000001E` | `KMODE_EXCEPTION_NOT_HANDLED` |
| `0x00000050` | `PAGE_FAULT_IN_NONPAGED_AREA` |
| `0x0000007E` | `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` |
| `0x0000007F` | `UNEXPECTED_KERNEL_MODE_TRAP` |
| `0x000000D1` | `DRIVER_IRQL_NOT_LESS_OR_EQUAL` |
| `0x000000E2` | `MANUALLY_INITIATED_CRASH` |
| `0x000000EF` | `CRITICAL_PROCESS_DIED` |
| `0x00000139` | `KERNEL_SECURITY_CHECK_FAILURE` |

For a complete list of supported bug check codes, see `bugcheck.cpp` or the [Microsoft Bug Check Code Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2).
