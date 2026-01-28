# Codemon Plugin

## Overview

The Codemon plugin (Machine **Code Mon**itor) monitors and dumps executable memory pages in a guest virtual machine. It is designed for malware analysis by tracking code execution patterns and capturing memory dumps of executable regions.

The plugin works by installing several traps:

1. **MmAccessFault Hook**: Monitors when `MmAccessFault` is called to commit virtual memory, capturing the faulting virtual address.

2. **Return Hook**: When `MmAccessFault` returns, the plugin obtains the physical address assigned to the virtual address.

3. **Execute Trap**: When instructions are fetched from a monitored physical frame for execution, the plugin dumps the memory (either a single page or the entire VAD node).

4. **Write Trap**: After an execution trap fires, it is replaced with a write trap. When memory is written to, the write trap is swapped back to an execute trap. This mechanism ensures memory is only re-dumped if it has been modified since the last dump.

This approach efficiently detects self-modifying code and unpacking behavior commonly used by malware.

## Supported Operating Systems

**Windows only**

The plugin hooks Windows-specific kernel functions:
- `MmAccessFault` - Windows memory manager access fault handler
- `KiSystemServiceHandler` - Windows system service exception handler

The plugin also filters out System32 and SysWOW64 DLLs by default (Windows system directories).

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dump_dir` | string | (required) | Directory to save memory dumps. A `dumps/` subdirectory will be created. |
| `filter_executable` | string | (none) | Filter monitoring to a specific executable name (case-insensitive match). |
| `log_everything` | boolean | false | Enable verbose logging of page faults, write faults, and all analyzed pages regardless of malware detection. |
| `dump_vad` | boolean | false | Dump entire VAD (Virtual Address Descriptor) nodes instead of single pages. VAD nodes larger than 1024 pages are skipped. |
| `analyse_system_dll_vad` | boolean | false | Include System32 and SysWOW64 DLLs in analysis. By default, these are excluded. |
| `default_benign` | boolean | false | Assume all memory is benign (do not dump). Set to true only when integrating a malware classifier. By default, all executed memory is considered potentially malicious and dumped. |

## How to Enable the Plugin

The codemon plugin is enabled by default in the build. To explicitly control it:

```bash
# Enable (default)
meson configure -Dplugin-codemon=true

# Disable
meson configure -Dplugin-codemon=false
```

Or when initially configuring the build:

```bash
meson setup build -Dplugin-codemon=true
```

## Output Format

### Console Output (execframe event)

When code execution is detected on a monitored page, the plugin outputs an `execframe` event with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `EventType` | string | Always "execframe" for execution events |
| `CR3` | hex | Control Register 3 value (page directory base) |
| `PageVA` | hex | Virtual address of the executed page |
| `VADBase` | hex | Starting virtual address of the VAD node |
| `VADEnd` | hex | Ending virtual address of the VAD node |
| `VADName` | string | Name of mapped file (DLL/EXE path) or "(no-mapped-file)" for dynamically allocated memory |
| `DumpSize` | integer | Size of the memory dump in bytes |
| `DumpFile` | string | Path to the dump file, or "(null)" if not dumped |
| `SHA256` | string | SHA256 hash of the dumped memory |
| `DumpID` | integer | Sequential dump identifier |
| `MetaFile` | string | Path to the metadata JSON file |
| `TrapPA` | hex | Physical address of the trap |
| `GFN` | hex | Guest Frame Number |

### Additional Event Types (with log_everything enabled)

**pagefault event** - Logged when a new page is committed:

| Field | Type | Description |
|-------|------|-------------|
| `EventType` | string | "pagefault" |
| `CR3` | hex | Control Register 3 value |
| `VA` | hex | Virtual address of the faulted page |
| `PA` | hex | Physical address assigned to the page |

**writefault event** - Logged when a monitored page is written to:

| Field | Type | Description |
|-------|------|-------------|
| `EventType` | string | "writefault" |
| `FrameVA` | hex | Virtual address of the written frame |
| `TrapPA` | hex | Physical address of the trap |
| `CR3` | hex | Control Register 3 value |
| `GFN` | hex | Guest Frame Number |

### Metadata File Format (JSON)

Each dump generates a `.metafile` JSON file containing:

```json
{
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 5678,
  "TID": 9012,
  "UserID": 0,
  "ProcessName": "malware.exe",
  "EventUID": 12345,
  "CR3": "0x1a2b3c4d",
  "PageVA": "0x7ff600000000",
  "VADBase": "0x7ff600000000",
  "VADEnd": "0x7ff600001fff",
  "VADName": "C:\\Windows\\System32\\ntdll.dll",
  "DumpSize": "0x1000",
  "DumpFile": "/path/to/dumps/7ff600000000_a1b2c3d4e5f6g7h8.page",
  "SHA256": "a1b2c3d4e5f6g7h8...",
  "DumpID": 1,
  "TrapPA": "0x123456789",
  "GFN": "0x123456"
}
```

### Dump File Naming

Dump files are named using the format:
```
<base_address>_<first 16 chars of SHA256>.<extension>
```

Where extension is:
- `.page` - Single page dump (4KB)
- `.vad` - VAD node dump (when `dump_vad` is enabled)

Example: `7ff600000000_a1b2c3d4e5f6g7h8.page`

## Example Output

### execframe Event (JSON format)

```json
{
  "Plugin": "codemon",
  "TimeStamp": "1609459200.000000",
  "PID": 4532,
  "PPID": 2048,
  "TID": 4536,
  "UserID": 1000,
  "ProcessName": "sample.exe",
  "EventType": "execframe",
  "CR3": "0x1a3f5000",
  "PageVA": "0x7ff700120000",
  "VADBase": "0x7ff700120000",
  "VADEnd": "0x7ff700122fff",
  "VADName": "(no-mapped-file)",
  "DumpSize": 4096,
  "DumpFile": "/output/dumps/7ff700120000_abc123def456gh78.page",
  "SHA256": "abc123def456gh78901234567890abcdef1234567890abcdef1234567890abcd",
  "DumpID": 1,
  "MetaFile": "/output/dumps/7ff700120000_abc123def456gh78.metafile",
  "TrapPA": "0x2f5a1000",
  "GFN": "0x2f5a1"
}
```

### pagefault Event (with log_everything)

```json
{
  "Plugin": "codemon",
  "EventType": "pagefault",
  "CR3": "0x1a3f5000",
  "VA": "0x7ff700120000",
  "PA": "0x2f5a1000"
}
```

### writefault Event (with log_everything)

```json
{
  "Plugin": "codemon",
  "EventType": "writefault",
  "FrameVA": "0x7ff700120000",
  "TrapPA": "0x2f5a1000",
  "CR3": "0x1a3f5000",
  "GFN": "0x2f5a1"
}
```

## Notes

- Kernel-space addresses (addresses with the highest bit set) are ignored to maintain kernel integrity assumptions.
- Duplicate dumps are avoided by tracking SHA256 hashes of previously dumped memory regions.
- Very large VAD nodes (1024+ pages) are skipped in VAD dump mode to avoid performance issues with 32-bit compatibility layers.
- The plugin was developed as part of a master's thesis at FAU Erlangen-Nurnberg in cooperation with Politecnico di Milano (2020/2021).
