# Memdump Plugin

## Overview

The memdump plugin for DRAKVUF automatically extracts memory regions from a monitored virtual machine based on various heuristics designed to detect and capture potentially malicious code. It hooks several Windows NT kernel functions to identify suspicious memory operations and dumps the relevant memory regions to disk for offline analysis.

The plugin is particularly useful for:
- Capturing unpacked malware payloads
- Detecting shellcode injection
- Monitoring process hollowing techniques
- Extracting .NET assemblies loaded from memory
- Identifying code hidden in RWX (Read-Write-Execute) memory regions

## Supported Operating Systems

**Windows only.** The plugin hooks Windows NT kernel functions and relies on Windows-specific structures such as MMVAD (Memory Manager Virtual Address Descriptors), PEB (Process Environment Block), and LDR_DATA_TABLE_ENTRY.

The plugin supports both 32-bit and 64-bit Windows guests, including WoW64 processes (32-bit processes running on 64-bit Windows).

## Detection Heuristics

The plugin triggers memory dumps based on the following conditions:

| Hook Target | Trigger Condition | Dump Reason |
|------------|-------------------|-------------|
| `NtFreeVirtualMemory` | Memory region starts with "MZ" magic bytes | "Possible binary detected" |
| `NtFreeVirtualMemory` | Memory region has RWX permissions and size > 0x1000 | "Interesting RWX memory" |
| `NtFreeVirtualMemory` | Memory region has RWX permissions (shellcode detection) | "Possible shellcode detected" |
| `NtProtectVirtualMemory` | Memory region starts with "MZ" magic bytes | "Possible binary detected" |
| `NtWriteVirtualMemory` | Cross-process write operation | "NtWriteVirtualMemory called" |
| `NtTerminateProcess` | Process terminating itself (stack analysis) | "Stack heuristic" |
| `NtCreateThreadEx` | Remote thread creation pointing to executable memory | "CreateRemoteThread heuristic" |
| `NtSetInformationThread` | WoW64 context modification (process hollowing detection) | "SetThreadContext heuristic" |
| .NET `AssemblyNative::LoadImage` | Assembly loaded from memory | ".NET AssemblyNative::LoadImage" |

## Configuration Options

### Command Line Options

| Option | Description |
|--------|-------------|
| `--memdump-dir <directory>` | Directory where memory dumps are stored. If not specified, the plugin runs in "dry run" mode and only logs events without saving dumps. |
| `--json-clr <path>` | JSON profile for clr.dll (enables .NET 4.x assembly hooking) |
| `--json-mscorwks <path>` | JSON profile for mscorwks.dll (enables .NET 2.x/3.x assembly hooking) |
| `--dll-hooks-list <file>` | List of DLL functions to hook for stack-based memory dumping |
| `--userhook-no-addr` | Suppress printing addresses of string arguments |

### Disable Flags

Individual hooks can be disabled using these flags:

| Option | Disables Hook On |
|--------|-----------------|
| `--memdump-disable-free-vm` | `NtFreeVirtualMemory` |
| `--memdump-disable-protect-vm` | `NtProtectVirtualMemory` |
| `--memdump-disable-write-vm` | `NtWriteVirtualMemory` |
| `--memdump-disable-terminate-proc` | `NtTerminateProcess` |
| `--memdump-disable-create-thread` | `NtCreateThreadEx` |
| `--memdump-disable-set-thread` | `NtSetInformationThread` (64-bit only, requires WoW64 JSON profile) |
| `--memdump-disable-shellcode-detect` | RWX shellcode detection via `NtFreeVirtualMemory` |

## How to Enable the Plugin

### Build Configuration

The plugin is enabled by default in the meson build system. To explicitly enable or disable it:

```bash
# Enable (default)
meson setup build -Dplugin-memdump=true

# Disable
meson setup build -Dplugin-memdump=false
```

### Runtime Usage

```bash
drakvuf -r <rekall_profile> -d <domain_name> --memdump-dir /path/to/dumps
```

## Output Format

### Console/Log Output

Each memory dump event produces a log line with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `DumpReason` | String | Why the dump was triggered (e.g., "Possible binary detected", "Stack heuristic") |
| `DumpPID` | Number | Process ID of the dumping process |
| `DumpAddr` | Hex | Base address of the dumped memory region |
| `DumpSize` | Hex | Size of the dump in bytes |
| `DumpFilename` | String | Name of the dump file (or "(not configured)" if no dump directory specified) |
| `DumpsCount` | Number | Sequential dump counter |

For `NtWriteVirtualMemory` events, additional fields are included:

| Field | Type | Description |
|-------|------|-------------|
| `TargetPID` | Number | PID of the target process being written to |
| `WriteAddr` | Hex | Target address in the remote process |

### Dump File Naming

Memory dump files are named using the format:
```
<base_address>_<sha256_hash_prefix>
```

Where:
- `<base_address>` is the hexadecimal virtual address of the dump
- `<sha256_hash_prefix>` is the first 16 characters of the SHA256 hash of the dump contents

This naming scheme enables:
- Easy identification of the original memory location for disassembly
- Automatic deduplication of identical memory regions

### Metadata Files

For each dump, a metadata file is created at:
```
<memdump_dir>/memdump.<sequence_number>.metadata
```

The metadata file contains JSON with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `Method` | String | The trap/hook name that triggered the dump |
| `DumpReason` | String | Human-readable reason for the dump |
| `DumpAddress` | Hex String | Base address of the dump (e.g., "0x7ff12340000") |
| `DumpSize` | Hex String | Size in bytes (e.g., "0x1000") |
| `PID` | Number | Process ID |
| `PPID` | Number | Parent process ID |
| `ProcessName` | String | Name of the process |
| `DataFileName` | String | Name of the corresponding dump file |
| `SequenceNumber` | Number | Sequential identifier for this dump |

For cross-process write operations, additional fields are included:

| Field | Type | Description |
|-------|------|-------------|
| `TargetPID` | Number | Target process PID |
| `TargetProcessName` | String | Target process name |
| `TargetBaseAddress` | Hex String | Target address in remote process |

## Example Output

### Console Output (JSON format)

Standard dump event:
```json
{
  "Plugin": "memdump",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 5678,
  "ProcessName": "malware.exe",
  "Method": "NtFreeVirtualMemory",
  "DumpReason": "Possible binary detected",
  "DumpPID": 1234,
  "DumpAddr": "0x400000",
  "DumpSize": "0x10000",
  "DumpFilename": "400000_a1b2c3d4e5f67890",
  "DumpsCount": 1
}
```

Cross-process write event:
```json
{
  "Plugin": "memdump",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 5678,
  "ProcessName": "injector.exe",
  "Method": "NtWriteVirtualMemory",
  "DumpReason": "NtWriteVirtualMemory called",
  "DumpPID": 1234,
  "DumpAddr": "0x7ff00000",
  "DumpSize": "0x1000",
  "DumpFilename": "7ff00000_1234567890abcdef",
  "DumpsCount": 2,
  "TargetPID": 4321,
  "WriteAddr": "0x10000"
}
```

### Metadata File Example

```json
{
  "Method": "NtFreeVirtualMemory",
  "DumpReason": "Possible binary detected",
  "DumpAddress": "0x400000",
  "DumpSize": "0x10000",
  "PID": 1234,
  "PPID": 5678,
  "ProcessName": "malware.exe",
  "DataFileName": "400000_a1b2c3d4e5f67890",
  "SequenceNumber": 1
}
```

## Notes

- If `--memdump-dir` is not specified, the plugin operates in "dry run" mode: it logs all dump events but does not write files to disk.
- The `NtSetInformationThread` hook is only active on 64-bit systems with a WoW64 JSON profile provided (via `-w` option).
- Usermode hooks for DLL functions require the `--dll-hooks-list` configuration file.
- The .NET hooks require the appropriate CLR/mscorwks JSON profiles to be provided.
