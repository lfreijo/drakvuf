# Procdump Plugin

## Overview

The procdump plugin captures process memory dumps when Windows processes terminate. It hooks the `NtTerminateProcess` system call and extracts the virtual address space of the terminating process, saving it in Windows MiniDump format. This is useful for malware analysis, forensics, and capturing the runtime state of processes for post-mortem analysis.

When a process calls `NtTerminateProcess` on itself (handle 0 or 0xffffffff), the plugin:

1. Traverses the process's Virtual Address Descriptor (VAD) tree to enumerate memory regions
2. Filters VADs to include only committed memory (allocated with `NtAllocateVirtualMemory`) and mapped images (DLLs/EXEs)
3. Creates a MiniDump header with system information, thread context, and memory layout
4. Dumps memory regions using either memory mapping (`vmi_mmap_guest`) or kernel injection (`RtlCopyMemoryNonTemporal`)
5. Writes the dump to disk, optionally with gzip compression

## Supported Operating Systems

- **Windows only** (32-bit and 64-bit)

The plugin relies on Windows-specific kernel functions and data structures:
- `NtTerminateProcess` - syscall hook trigger
- `ExAllocatePoolWithTag` - kernel pool allocation for memory copying
- `RtlCopyMemoryNonTemporal` - safe memory copy for DLL regions
- `MmCleanProcessAddressSpace` - second-stage hook for DLL dumping
- MMVAD (Memory Manager Virtual Address Descriptor) structures

## Configuration Options

### Command Line Arguments

| Option | Description |
|--------|-------------|
| `--procdump-dir <path>` | Directory where process dumps will be saved. **Required** to enable the plugin. |
| `--compress-procdumps` | Enable gzip compression for dump files. |

### Example Usage

```bash
drakvuf -r /path/to/windows.json -d domain_name --procdump-dir /tmp/dumps
```

With compression:

```bash
drakvuf -r /path/to/windows.json -d domain_name --procdump-dir /tmp/dumps --compress-procdumps
```

## How to Enable the Plugin (Meson)

The plugin is enabled by default. To explicitly control it during build configuration:

```bash
# Enable (default)
meson setup build -Dplugin-procdump=true

# Disable
meson setup build -Dplugin-procdump=false
```

## Output Format

### Console Output

When a process dump completes, the plugin outputs an event with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `DumpReason` | String | The reason for the dump. Currently always `"TerminateProcess"`. |
| `DumpSize` | Number | Total size of the dumped memory in bytes. |
| `SN` | Number | Sequential dump number (0-indexed counter of dumps in this session). |

Standard DRAKVUF event fields are also included (timestamp, process name, PID, PPID, TID, etc.).

### Dump Files

For each dumped process, two files are created in the specified `--procdump-dir`:

1. **Data file**: `procdump.<SN>` - The actual memory dump in Windows MiniDump format
2. **Metadata file**: `procdump.<SN>.metadata` - JSON file with dump metadata

#### Metadata File Format (JSON)

```json
{
    "DumpSize": "0x1a3b000",
    "PID": 1234,
    "PPID": 5678,
    "ProcessName": "malware.exe",
    "Compression": "gzip",
    "DataFileName": "procdump.0"
}
```

| Field | Description |
|-------|-------------|
| `DumpSize` | Size of the dump in hexadecimal format |
| `PID` | Process ID of the dumped process |
| `PPID` | Parent process ID |
| `ProcessName` | Name of the dumped process |
| `Compression` | Compression method: `"gzip"` or `"none"` |
| `DataFileName` | Name of the corresponding data file |

### MiniDump File Structure

The dump file uses the Windows MiniDump format and includes:

- **Header**: MiniDump signature (`MDMP`), version, timestamp, and flags
- **System Info Stream**: Processor architecture (x86/x64), Windows version, build number, CPU vendor information
- **Thread List Stream**: Thread ID, TEB address, stack information, and CPU register context
- **Memory List Stream**: Memory range descriptors mapping virtual addresses to file offsets
- **Memory Data**: Raw memory contents following the header

The dump can be analyzed with standard tools that support Windows MiniDump format.

## Example Output

### Console Event (JSON format)

```json
{
    "Plugin": "procdump",
    "TimeStamp": "1704067200.123456",
    "VCPU": 0,
    "CR3": "0x1a3b000",
    "ProcessName": "malware.exe",
    "UserName": "SYSTEM",
    "UserId": 0,
    "PID": 1234,
    "PPID": 5678,
    "TID": 4321,
    "DumpReason": "TerminateProcess",
    "DumpSize": 27389952,
    "SN": 0
}
```

### Console Event (Default/KV format)

```
[PROCDUMP] TIME:1704067200.123456 VCPU:0 CR3:0x1a3b000 malware.exe SYSTEM(0) 1234/4321 DumpReason:"TerminateProcess" DumpSize:27389952 SN:0
```

## Technical Notes

- VADs larger than 1GB are skipped to avoid excessive memory consumption
- DLLs (VadType=2) are dumped in a second stage using `RtlCopyMemoryNonTemporal` to avoid potential BSODs
- Memory regions that cannot be read are zero-filled to maintain proper alignment
- The plugin uses a pool of kernel memory for safe memory copying operations
- Maximum of 256 memory ranges can be described in the MiniDump header metadata
