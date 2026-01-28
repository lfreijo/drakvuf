# Syscalls Plugin

## Overview

The syscalls plugin monitors and logs system calls made by processes running inside the guest virtual machine. It hooks into kernel syscall entry points to capture syscall invocations and optionally their return values. The plugin extracts detailed information about each syscall including the syscall number, name, arguments with their types and values, and the calling process context.

For each monitored syscall, the plugin:
- Identifies the syscall by number and name
- Extracts and parses syscall arguments based on known type definitions
- Captures process context (PID, process name, thread information)
- Optionally captures syscall return values (sysret)

## Supported Operating Systems

### Windows
- Supports both 32-bit and 64-bit Windows guests
- Monitors NT kernel syscalls (ntoskrnl) from the System Service Descriptor Table (SSDT)
- Optionally monitors Win32k (GUI subsystem) syscalls when a win32k profile is provided
- Tracks the privilege mode (User/Kernel) of syscall callers
- Resolves the calling module (DLL) that initiated the syscall
- Whitelisted system libraries tracked: gdi32.dll, imm32.dll, ntdll.dll, user32.dll, wow64win.dll

### Linux
- Supports both 32-bit and 64-bit Linux guests (including Android)
- Hooks the syscall dispatcher functions:
  - Modern kernels (6.x+): `x64_sys_call` or `do_syscall_64`
  - 32-bit compatibility: `do_int80_syscall_32`
  - Legacy kernels: individual `__x64_sys_*` and `__ia32_sys_*` functions
- Supports both x64 and x32 (32-bit compatibility) syscalls
- Handles different kernel calling conventions for syscall argument passing

## Configuration Options

The plugin accepts the following configuration options via `syscalls_config`:

| Option | Description |
|--------|-------------|
| `syscalls_filter_file` | Path to a text file containing syscall names to monitor (one per line). If not specified, all syscalls are monitored. |
| `win32k_profile` | Path to the win32k.sys JSON profile for Windows. Required to monitor Win32k (GUI) syscalls. |
| `disable_sysret` | When set to `true`, disables monitoring of syscall return values. This can improve performance. |

### Syscall Filter File Format

The filter file should contain one syscall name per line. Only syscalls listed in this file will be monitored:

```
NtCreateFile
NtOpenProcess
NtWriteFile
open
read
write
mmap
```

**Note:** The `nanosleep` syscall is particularly expensive to intercept and can significantly slow down the guest. It is recommended to exclude it using the filter file for performance-sensitive deployments.

## How to Enable the Plugin

The syscalls plugin is enabled by default in the build. To explicitly control it during the meson build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-syscalls=true

# Disable the plugin
meson setup build -Dplugin-syscalls=false
```

To enable Win32k syscall monitoring on Windows, provide the win32k profile path when running DRAKVUF.

## Output Format

The plugin emits two types of events: `syscall` (on syscall entry) and `sysret` (on syscall return).

### Syscall Entry Event Fields

| Field | Description |
|-------|-------------|
| `Plugin` | Always "syscall" |
| `Method` | The syscall name (e.g., "NtCreateFile", "open") |
| `TimeStamp` | Event timestamp |
| `PID` | Process ID of the calling process |
| `PPID` | Parent process ID |
| `TID` | Thread ID |
| `UserName` | Username associated with the process |
| `UserId` | User ID |
| `ProcessName` | Name of the calling process |
| `ThreadName` | Name of the calling thread (Linux only) |
| `Module` | Syscall table type ("nt", "win32k", "x64", "x32") |
| `vCPU` | Virtual CPU number |
| `CR3` | Page table base register value |
| `Syscall` | Syscall number |
| `NArgs` | Number of arguments |
| `Type` | Syscall type ("x64" or "x32" for Linux) |
| `PreviousMode` | "User" or "Kernel" (Windows only) |
| `FromModule` | Module (DLL) that called the syscall (Windows only) |
| `FromParentModule` | Parent module in the call chain (Windows only) |
| `<ArgName>` | Syscall arguments with their names and values |

### Syscall Return Event Fields

| Field | Description |
|-------|-------------|
| `Plugin` | Always "sysret" |
| `Method` | The syscall name |
| `Module` | Syscall table type |
| `vCPU` | Virtual CPU number |
| `CR3` | Page table base register value |
| `Syscall` | Syscall number |
| `Ret` | Return value (hex) |
| `Info` | Human-readable return status (e.g., NTSTATUS string for Windows) |

### Argument Value Formatting

- Pointer arguments are displayed in hexadecimal
- String arguments (PUNICODE_STRING, char*) are extracted and displayed as strings
- File handles are resolved to filenames when possible
- Object attributes are parsed to extract filenames
- Special flag types are parsed:
  - `mmap` protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
  - `prctl` options (PR_SET_NAME, PR_GET_SECCOMP, etc.)
  - `arch_prctl` codes (ARCH_SET_FS, ARCH_SET_GS, etc.)

## Example Output

### Linux syscall (JSON format)
```json
{
  "Plugin": "syscall",
  "TimeStamp": "1706000000.000000",
  "PID": 1234,
  "PPID": 1,
  "TID": 1234,
  "ProcessName": "bash",
  "Method": "openat",
  "ThreadName": "bash",
  "Module": "x64_sys_call",
  "vCPU": 0,
  "CR3": "0x1a2b3c4d",
  "Syscall": 257,
  "NArgs": 4,
  "Type": "x64",
  "dirfd": "0xffffff9c",
  "pathname": "/etc/passwd",
  "flags": "0x0",
  "mode": "0x0"
}
```

### Linux sysret (JSON format)
```json
{
  "Plugin": "sysret",
  "TimeStamp": "1706000000.000001",
  "PID": 1234,
  "ProcessName": "bash",
  "Method": "openat",
  "Module": "x64_sys_call",
  "vCPU": 0,
  "CR3": "0x1a2b3c4d",
  "Syscall": 257,
  "Ret": "0x3",
  "Info": ""
}
```

### Windows syscall (JSON format)
```json
{
  "Plugin": "syscall",
  "TimeStamp": "1706000000.000000",
  "PID": 4567,
  "PPID": 1000,
  "ProcessName": "notepad.exe",
  "Method": "NtCreateFile",
  "Module": "nt",
  "vCPU": 0,
  "CR3": "0x1a2b3c4d",
  "Syscall": 85,
  "NArgs": 11,
  "PreviousMode": "User",
  "FromModule": "\\windows\\system32\\ntdll.dll",
  "FileHandle": "0x0",
  "DesiredAccess": "0x80100000",
  "ObjectAttributes": "\\??\\C:\\Users\\test\\document.txt"
}
```

### Windows sysret (JSON format)
```json
{
  "Plugin": "sysret",
  "TimeStamp": "1706000000.000001",
  "PID": 4567,
  "ProcessName": "notepad.exe",
  "Method": "NtCreateFile",
  "Module": "nt",
  "vCPU": 0,
  "CR3": "0x1a2b3c4d",
  "Syscall": 85,
  "Ret": "0x0",
  "Info": "STATUS_SUCCESS"
}
```

## Supported Syscalls

### Linux
The plugin includes definitions for over 330 Linux syscalls covering:
- File operations (open, read, write, close, stat, etc.)
- Memory management (mmap, mprotect, brk, etc.)
- Process control (clone, fork, execve, exit, etc.)
- Networking (socket, connect, bind, listen, etc.)
- IPC (shmget, semget, msgget, etc.)
- Signals (rt_sigaction, kill, etc.)
- Security (prctl, seccomp, bpf, etc.)

### Windows
The plugin includes definitions for hundreds of NT kernel syscalls and Win32k syscalls covering:
- File operations (NtCreateFile, NtReadFile, NtWriteFile, etc.)
- Process/thread management (NtCreateProcess, NtCreateThread, etc.)
- Memory management (NtAllocateVirtualMemory, NtProtectVirtualMemory, etc.)
- Registry operations (NtCreateKey, NtSetValueKey, etc.)
- Security (NtOpenProcessToken, NtAdjustPrivilegesToken, etc.)
- ALPC/LPC communication
- And many more NT* functions
