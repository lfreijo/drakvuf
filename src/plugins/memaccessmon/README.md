# memaccessmon Plugin

## Overview

The `memaccessmon` plugin monitors cross-process virtual memory read and write operations in Windows guest virtual machines. It hooks the following Windows NT syscalls:

- `NtWriteVirtualMemory` - Monitors processes writing to another process's memory
- `NtReadVirtualMemory` - Monitors processes reading from another process's memory
- `NtReadVirtualMemoryEx` - Monitors extended read operations from another process's memory

When a process attempts to read or write memory in a different process (identified by a process handle other than `-1`/self), the plugin logs details about the target process, the memory region being accessed, and the number of bytes involved.

The plugin uses Windows Memory Manager Virtual Address Descriptors (MMVADs) to resolve information about the target memory region, including the backing file name if the memory region is mapped from a file.

This is useful for detecting process injection techniques, credential dumping, and other cross-process memory manipulation activities commonly used by malware.

## Supported Operating Systems

- **Windows**: Fully supported
- **Linux**: Not supported (hooks Windows-specific NT syscalls)

## Configuration Options

This plugin has no configuration options. It automatically monitors all cross-process memory read/write operations when enabled.

## How to Enable the Plugin

### Using Meson (Recommended)

The plugin is enabled by default. To explicitly enable or disable it during build configuration:

```bash
# Enable (default)
meson setup build -Dplugin-memaccessmon=true

# Disable
meson setup build -Dplugin-memaccessmon=false
```

### Using Autotools

```bash
# Enable (default)
./configure --enable-plugin-memaccessmon

# Disable
./configure --disable-plugin-memaccessmon
```

## Output Format

The plugin outputs events in the standard DRAKVUF output format (JSON, CSV, KV, or default). Each event contains standard fields plus plugin-specific fields.

### Standard Fields

| Field | Type | Description |
|-------|------|-------------|
| Plugin | string | Always "memaccessmon" |
| TimeStamp | string | Timestamp of the event (seconds.microseconds) |
| PID | number | Process ID of the process performing the memory access |
| PPID | number | Parent process ID of the accessing process |
| TID | number | Thread ID performing the memory access |
| UserId | number | User ID of the accessing process |
| ProcessName | string | Name of the process performing the memory access |
| Method | string | The syscall being monitored (NtWriteVirtualMemory, NtReadVirtualMemory, or NtReadVirtualMemoryEx) |
| EventUID | hex | Unique identifier for this event |

### Plugin-Specific Fields

| Field | Type | Description |
|-------|------|-------------|
| TargetName | string | Name of the target process whose memory is being accessed (null if unavailable) |
| TargetPID | number | Process ID of the target process |
| FileName | string | File name backing the memory region (e.g., DLL path) if the region is file-mapped (null if not file-backed) |
| Bytes | hex | Number of bytes being read or written |

## Example Output

### JSON Format

```json
{"Plugin":"memaccessmon","TimeStamp":"1234567890.123456","PID":4532,"PPID":1024,"TID":5678,"UserId":0,"ProcessName":"malware.exe","Method":"NtWriteVirtualMemory","EventUID":"0x1234","TargetName":"explorer.exe","TargetPID":2048,"FileName":"C:\\Windows\\System32\\ntdll.dll","Bytes":"0x1000"}
```

### JSON Format (without file backing)

```json
{"Plugin":"memaccessmon","TimeStamp":"1234567890.123456","PID":4532,"PPID":1024,"TID":5678,"UserId":0,"ProcessName":"malware.exe","Method":"NtReadVirtualMemory","EventUID":"0x1235","TargetName":"lsass.exe","TargetPID":672,"FileName":null,"Bytes":"0x200"}
```

## Notes

- The plugin ignores self-reads/writes (when the process handle is `-1`, indicating the process is accessing its own memory)
- Memory region information is cached per-PID to improve performance when multiple accesses occur to the same region
- The MMVAD lookup provides the virtual address range and any associated file mapping for the target memory region
