# Filetracer Plugin

## Overview

The filetracer plugin monitors and logs file system operations in virtual machines running under DRAKVUF. It intercepts file-related system calls and kernel functions to provide visibility into file access patterns, including file creation, opening, reading, writing, renaming, deletion, and attribute modifications.

This plugin is useful for:
- Malware analysis (detecting file drops, modifications, and data exfiltration)
- Security monitoring and forensics
- Understanding application file I/O behavior
- Tracking file permission and ownership changes

## Supported Operating Systems

### Windows
The Windows implementation hooks the following NT kernel functions:
- `NtCreateFile` - File creation and opening with full create options
- `NtOpenFile` - File opening
- `NtOpenDirectoryObject` - Directory object opening
- `NtQueryAttributesFile` - Query basic file attributes
- `NtQueryFullAttributesFile` - Query extended file attributes
- `NtSetInformationFile` - File information modifications (rename, delete, truncate, attributes)
- `NtReadFile` - File read operations
- `NtWriteFile` - File write operations
- `NtQueryInformationFile` - Query file information

### Linux
The Linux implementation supports two modes:

**Modern Kernels (6.x+):**
Uses a unified syscall hook (`x64_sys_call`) to intercept file-related system calls including:
- `open`, `openat`, `openat2`, `creat` - File opening/creation
- `read`, `write`, `pread64`, `pwrite64` - File I/O
- `close` - File closing
- `lseek` - File position seeking
- `stat`, `fstat`, `lstat` - File status queries
- `rename`, `renameat`, `renameat2` - File renaming
- `unlink`, `unlinkat` - File deletion
- `mkdir`, `mkdirat`, `rmdir` - Directory operations
- `link`, `linkat`, `symlink`, `symlinkat`, `readlink`, `readlinkat` - Link operations
- `chmod`, `fchmod`, `fchmodat` - Permission changes
- `chown`, `fchown`, `lchown`, `fchownat` - Ownership changes
- `access`, `faccessat` - Access checks
- `truncate`, `ftruncate` - File truncation
- `chdir`, `fchdir` - Directory changes
- `memfd_create` - Anonymous file creation
- `dup`, `dup2` - File descriptor duplication
- `sendfile` - File transfer between descriptors

**Legacy Kernels (pre-6.x):**
Falls back to hooking VFS (Virtual File System) layer functions:
- `do_filp_open` - File opening
- `vfs_read`, `vfs_write` - File I/O
- `filp_close` - File closing
- `vfs_llseek` - File seeking
- `vfs_mknod` - Device node creation
- `vfs_rename` - File renaming
- `do_truncate` - File truncation
- `vfs_allocate` - File space allocation
- `chmod_common`, `chown_common` - Permission/ownership changes
- `vfs_utimes` - Timestamp modifications
- `do_faccessat` - Access checks
- `vfs_mkdir`, `vfs_rmdir` - Directory operations
- `set_fs_pwd`, `set_fs_root` - Working directory changes
- `vfs_link`, `vfs_unlink`, `vfs_symlink`, `vfs_readlink` - Link operations
- `__x64_sys_memfd_create` - Anonymous file creation

## Configuration Options

### Windows-specific Configuration

The plugin accepts an optional `ole32_profile` configuration parameter that provides additional type information for parsing `FILE_RENAME_INFORMATION`, `FILE_ALL_INFORMATION`, and related structures. When provided, the plugin can extract more detailed information for file rename operations and full file information queries.

```c
struct filetracer_config
{
    const char* ole32_profile;  // Path to ole32 JSON profile (optional)
};
```

## How to Enable the Plugin

The filetracer plugin is enabled by default. To explicitly control it during the build:

### Enable (default)
```bash
meson setup build -Dplugin-filetracer=true
```

### Disable
```bash
meson setup build -Dplugin-filetracer=false
```

## Output Format

The plugin outputs events using DRAKVUF's standard output formatting system, supporting multiple output formats (default, CSV, KV, JSON).

### Common Output Fields

All events include standard DRAKVUF process context fields:
- Timestamp
- vCPU number
- CR3 (page table base)
- Process name
- User ID
- Process ID (PID)
- Thread ID (TID)
- Parent PID (PPID)

### Windows-specific Output Fields

#### NtCreateFile / NtOpenFile Events
| Field | Description |
|-------|-------------|
| `FileName` | Full path of the file being accessed |
| `FileHandle` | Handle value returned (hex) |
| `ObjectAttributes` | Object attribute flags (e.g., OBJ_CASE_INSENSITIVE, OBJ_INHERIT) |
| `IoStatusBlock` | I/O status information value |
| `SecurityDescriptor` | Security descriptor details including Control, Owner, Group, Sacl, Dacl |
| `DesiredAccess` | Requested access rights (e.g., FILE_READ_DATA, GENERIC_READ) |
| `FileAttributes` | File attribute flags (e.g., FILE_ATTRIBUTE_NORMAL) |
| `ShareAccess` | Share mode flags (e.g., FILE_SHARE_READ) |
| `CreateDisposition` | Create disposition (e.g., FILE_OPEN, FILE_CREATE) |
| `CreateOptions` / `OpenOptions` | Create/open option flags |
| `Status` | NTSTATUS return value (hex) |

#### File Information Events
| Field | Description |
|-------|-------------|
| `Operation` | Type of operation (e.g., FileBasicInformation, FileRenameInformation) |
| `FileHandle` | File handle being operated on |
| `FileName` | File path |
| `CreationTime` | File creation timestamp (Unix epoch) |
| `LastAccessTime` | Last access timestamp (Unix epoch) |
| `LastWriteTime` | Last write timestamp (Unix epoch) |
| `ChangeTime` | Last change timestamp (Unix epoch) |
| `FileAttributes` | File attribute flags |
| `AllocationSize` | Allocated size on disk (hex) |
| `EndOfFile` | Logical end of file position (hex) |
| `FileSize` | File size for truncation operations |
| `FileSrc` / `FileDst` | Source and destination paths for rename operations |

### Linux-specific Output Fields

| Field | Description |
|-------|-------------|
| `FileName` | File path being accessed |
| `Permissions` | File permissions in octal format |
| `Mode` | File type mode flags (e.g., MODE_S_IFREG for regular file) |
| `Flag` | Open flags (e.g., FLAG_O_RDWR) |
| `UID` | File owner user ID |
| `GID` | File owner group ID |
| `FileHandle` | File descriptor number |
| `ThreadName` | Name of the thread performing the operation |
| `Syscall` | System call name (modern kernel mode only) |
| Additional context-specific fields (count, offset, pos, oldname, newpath, etc.) |

## Example Output

### Windows - NtCreateFile (JSON format)
```json
{
  "Plugin": "filetracer",
  "TimeStamp": "1699900000.000000",
  "VCPU": 0,
  "CR3": "0x1aa000",
  "ProcessName": "notepad.exe",
  "UserId": 0,
  "PID": 1234,
  "TID": 5678,
  "PPID": 1000,
  "Method": "NtCreateFile",
  "FileName": "\\Device\\HarddiskVolume2\\Users\\user\\Documents\\test.txt",
  "FileHandle": "0x1a4",
  "ObjectAttributes": "OBJ_CASE_INSENSITIVE",
  "IoStatusBlock": 1,
  "SecurityDescriptor": [],
  "DesiredAccess": "GENERIC_WRITE|SYNCHRONIZE",
  "FileAttributes": "FILE_ATTRIBUTE_NORMAL",
  "ShareAccess": "FILE_SHARE_READ",
  "CreateDisposition": "FILE_OVERWRITE_IF",
  "CreateOptions": "FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE",
  "Status": "0x0"
}
```

### Windows - File Rename Operation
```json
{
  "Plugin": "filetracer",
  "Method": "NtSetInformationFile",
  "Operation": "FileRenameInformation",
  "FileSrc": "\\Device\\HarddiskVolume2\\temp\\old.txt",
  "FileDst": "\\Device\\HarddiskVolume2\\temp\\new.txt",
  "FileHandle": "0x1a8"
}
```

### Windows - File Delete Operation
```json
{
  "Plugin": "filetracer",
  "Method": "NtSetInformationFile",
  "Operation": "FileDispositionInformation",
  "FileName": "\\Device\\HarddiskVolume2\\temp\\delete_me.txt",
  "FileHandle": "0x1ac"
}
```

### Linux - File Open (Modern Kernel)
```json
{
  "Plugin": "filetracer",
  "ProcessName": "bash",
  "PID": 1234,
  "Syscall": "openat",
  "ThreadName": "bash",
  "FileName": "/etc/passwd",
  "dirfd": "-100",
  "flags": "0"
}
```

### Linux - File Read (Legacy VFS Hook)
```json
{
  "Plugin": "filetracer",
  "Method": "vfs_read",
  "ProcessName": "cat",
  "Permissions": "644",
  "ThreadName": "cat",
  "FileName": "/home/user/document.txt",
  "Mode": "MODE_S_IFREG",
  "UID": "1000",
  "GID": "1000",
  "count": "4096",
  "pos": "0"
}
```

### Linux - Directory Creation
```json
{
  "Plugin": "filetracer",
  "Method": "vfs_mkdir",
  "ProcessName": "mkdir",
  "Permissions": "755",
  "ThreadName": "mkdir",
  "FileName": "/home/user/new_directory",
  "new_permissions": "755",
  "new_mode": "MODE_S_IFDIR"
}
```

### Linux - File Rename
```json
{
  "Plugin": "filetracer",
  "Method": "vfs_rename",
  "ProcessName": "mv",
  "Permissions": "644",
  "ThreadName": "mv",
  "FileName": "/home/user/newname.txt",
  "old_name": "/home/user/oldname.txt"
}
```

## Notes

- The plugin automatically detects the guest OS type (Windows/Linux) and uses the appropriate implementation
- For Windows, some advanced features (file rename tracking, FILE_ALL_INFORMATION parsing) require the optional ole32 profile
- For Linux, the plugin automatically detects the kernel version and uses the appropriate hooking method
- Linux kernel version 5.12+ changed function signatures for several VFS functions; the plugin handles both old and new signatures automatically
- Output timestamps for Windows are converted from Windows FILETIME to Unix epoch format
