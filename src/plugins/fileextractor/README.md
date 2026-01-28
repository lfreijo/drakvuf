# File Extractor Plugin

## Overview

The fileextractor plugin monitors and extracts files that are written or deleted by processes running inside a virtual machine. It intercepts file I/O operations at the kernel level to capture file contents before they are modified, deleted, or closed. This is particularly useful for malware analysis, forensics, and monitoring file activity in sandboxed environments.

The plugin tracks files based on three trigger reasons:
- **WriteFile**: A file is being written to
- **CreateSection**: A memory-mapped section is created for a file with write access
- **DeleteFile**: A file is marked for deletion

## Supported Operating Systems

### Windows
Full support with extraction capabilities. Hooks the following NT kernel functions:
- `NtCreateFile` / `NtOpenFile` - Detects files opened with delete-on-close or append flags
- `NtWriteFile` - Captures file write operations
- `NtSetInformationFile` - Detects file deletion requests and end-of-file changes
- `NtClose` - Triggers final file extraction when handle is closed
- `ZwCreateSection` - Detects memory-mapped file modifications

The Windows implementation uses syscall injection to extract file contents by:
1. Querying volume and file information
2. Creating a memory section from the file
3. Mapping the section into memory
4. Copying the file contents to a kernel pool
5. Reading the data from the guest VM

### Linux
Support for x86_64 systems. Hooks the syscall entry point (`x64_sys_call` on kernel 6.x+ or `do_syscall_64` on older kernels) and intercepts:
- `write` (syscall 1)
- `pwrite64` (syscall 18)

The Linux implementation captures write buffer contents directly from user space when write syscalls occur.

## Configuration Options

The plugin accepts the following configuration parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `dump_folder` | string | **Required.** Path to the directory where extracted files will be saved. |
| `timeout` | uint32 | Timeout in seconds for file extraction operations. Used to prevent indefinite hangs when stopping the plugin. |
| `hash_size` | uint64 | Maximum file size (in MB) for SHA256 hash calculation. Files larger than this will not have their hash computed. Set to 0 for no limit. |
| `extract_size` | uint64 | Maximum file size (in MB) to extract. Files larger than this will be skipped with a "Too big file" message. Set to 0 for no limit. |
| `exclude_file` | string | Path to a file containing patterns of filenames to exclude from extraction. |

## How to Enable the Plugin

The plugin is enabled by default in the meson build system. To explicitly control it:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-fileextractor=true

# Disable the plugin
meson setup build -Dplugin-fileextractor=false
```

When running DRAKVUF, specify the dump folder to activate file extraction:

```bash
drakvuf -r <rekall_profile> -d <domain> --fileextractor-dump-folder /path/to/dump
```

## Output Format

### Main Output Events

The plugin emits events with the plugin name `fileextractor` containing the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `FileName` | string | The path/name of the file being extracted (escaped string) |
| `Size` | number | Size of the file in bytes |
| `FileHash` | string | SHA256 hash of the extracted file (optional, only if hash calculation succeeded) |
| `Flags` | hex | Raw file object flags value (Windows only) |
| `FlagsExpanded` | string | Human-readable representation of file flags (Windows only) |
| `SeqNum` | number | Unique sequence number assigned to this extracted file |
| `Reason` | string | Why the file was extracted: "WriteFile", "CreateSection", or "DeleteFile" |
| `isClosed` | number | Whether the file handle was closed (1) or still open (0) |

### Plugin Close Events (Windows)

When the plugin stops and files are still being tracked, it emits `fileextractor_close` events with additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `Time` | timestamp | Time when the close event was generated |
| `ProcessName` | string | Name of the process that opened the file |
| `PID` | number | Process ID |
| `PPID` | number | Parent process ID |

### Failure Events

When extraction fails, `fileextractor_fail` events are emitted:

| Field | Type | Description |
|-------|------|-------------|
| `FileName` | string | The file that failed to extract |
| `Message` | string | Description of the failure reason |

### Skip Events

When a file is excluded by filter, `fileextractor_skip` events are emitted:

| Field | Type | Description |
|-------|------|-------------|
| `FileName` | string | The file that was skipped |
| `Message` | string | Always "Excluded by filter" |

### Linux Output

For Linux, the `fileextractor` events include:

| Field | Type | Description |
|-------|------|-------------|
| `Reason` | string | Always "WriteFile" for Linux |
| `FileName` | string | Path to the file being written |
| `Size` | number | Size of the write operation |
| `DumpFile` | string | Path to the extracted file on the host |
| `ProcessName` | string | Name of the process performing the write |

## Output Files

### Windows

Extracted files are saved in the dump folder with the naming convention:
- `file.NNNNNN.mm` - The extracted file data (NNNNNN is a zero-padded sequence number)
- `file.NNNNNN.metadata` - JSON metadata file containing:
  - `FileName`: Original file path
  - `FileSize`: Size in bytes
  - `FileFlags`: File object flags with human-readable expansion
  - `SequenceNumber`: Sequence number
  - `ControlArea`: Memory control area address
  - `PID`: Process ID
  - `PPID`: Parent process ID
  - `ProcessName`: Name of the process
  - `FileHash`: SHA256 hash (added when file is closed)

### Linux

Extracted files are saved with the naming convention:
- `NNNNNNNN_<sanitized_filename>` - The extracted file data

## Example Output

### JSON Format (Windows)

```json
{
  "Plugin": "fileextractor",
  "TimeStamp": "1234567890.123456",
  "FileName": "\\Device\\HarddiskVolume2\\Users\\test\\malware.exe",
  "Size": 45056,
  "FileHash": "a1b2c3d4e5f6...",
  "Flags": "0x10000",
  "FlagsExpanded": "FO_DELETE_ON_CLOSE",
  "SeqNum": 1,
  "Reason": "DeleteFile",
  "isClosed": 1
}
```

### JSON Format (Linux)

```json
{
  "Plugin": "fileextractor",
  "TimeStamp": "1234567890.123456",
  "Reason": "WriteFile",
  "FileName": "/tmp/malicious_script.sh",
  "Size": 1024,
  "DumpFile": "/path/to/dump/00000001__tmp_malicious_script.sh",
  "ProcessName": "bash"
}
```

### Failure Output

```json
{
  "Plugin": "fileextractor_fail",
  "FileName": "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SYSTEM",
  "Message": "ZwCreateSection failed with status 0xc0000022"
}
```

## File Object Flags (Windows)

The plugin tracks and reports Windows file object flags including:

- `FO_FILE_OPEN` (0x00000001)
- `FO_SYNCHRONOUS_IO` (0x00000002)
- `FO_NO_INTERMEDIATE_BUFFERING` (0x00000008)
- `FO_WRITE_THROUGH` (0x00000010)
- `FO_SEQUENTIAL_ONLY` (0x00000020)
- `FO_CACHE_SUPPORTED` (0x00000040)
- `FO_FILE_MODIFIED` (0x00001000)
- `FO_FILE_SIZE_CHANGED` (0x00002000)
- `FO_CLEANUP_COMPLETE` (0x00004000)
- `FO_TEMPORARY_FILE` (0x00008000)
- `FO_DELETE_ON_CLOSE` (0x00010000)
- `FO_HANDLE_CREATED` (0x00040000)
- `FO_RANDOM_ACCESS` (0x00100000)

## Notes

- The Windows implementation uses syscall injection which temporarily modifies the guest VM state. The plugin handles state restoration automatically.
- Files opened by multiple handles are tracked individually; extraction occurs when the last handle is closed.
- The Linux implementation filters out writes to `/dev/`, `/proc/`, `/sys/`, sockets, pipes, and anonymous inodes to reduce noise.
- Large files may impact performance; use `extract_size` to limit extraction to smaller files.
