# Procmon Plugin

## Overview

The procmon (Process Monitor) plugin is a DRAKVUF plugin that monitors process-related activity within a guest virtual machine. It hooks into kernel functions to track:

- **Process creation** - New processes being spawned
- **Process termination** - Processes exiting with their exit status
- **Process/thread handle operations** - Opening handles to processes and threads
- **Signal delivery** (Linux) - Signals sent between processes
- **Process cloning** (Linux) - Fork/clone operations
- **Memory protection changes** (Windows) - Virtual memory protection modifications
- **Token privilege adjustments** (Windows) - Security privilege changes

On initialization, the plugin enumerates all currently running processes and outputs their information.

## Supported Operating Systems

### Windows

The Windows implementation hooks the following NT kernel functions:

| Function | Description |
|----------|-------------|
| `NtCreateUserProcess` | Monitors new user-mode process creation |
| `NtCreateProcessEx` | Monitors extended process creation |
| `NtTerminateProcess` | Monitors process termination |
| `MmCleanProcessAddressSpace` | Monitors process address space cleanup |
| `NtOpenProcess` | Monitors opening handles to processes |
| `NtOpenThread` | Monitors opening handles to threads |
| `NtProtectVirtualMemory` | Monitors memory protection changes |
| `NtAdjustPrivilegesToken` | Monitors security token privilege adjustments |

### Linux

The Linux implementation hooks the following kernel functions:

| Function | Description |
|----------|-------------|
| `begin_new_exec` | Monitors execve system calls (falls back to `do_execveat_common`) |
| `do_exit` | Monitors process/thread termination |
| `do_send_sig_info` | Monitors signal delivery (falls back to `send_signal`) |
| `kernel_clone` | Monitors fork/clone operations |

## Configuration Options

### Environment Variable Filter (Linux only)

The Linux implementation can filter which environment variables are captured and reported during execve events.

**Configuration file:** Specify a filter file path via the `procmon_filter_file` configuration option.

**Default filter:** If no filter file is provided, the following environment variables are captured by default:
- `LD_PRELOAD`
- `PWD`
- `OLDPWD`

**Filter file format:** One environment variable name per line.

## How to Enable the Plugin

The plugin is enabled by default. To explicitly control it during the build:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-procmon=true

# Disable the plugin
meson setup build -Dplugin-procmon=false
```

## Output Format

The plugin outputs events with the plugin name `procmon`. Output fields vary depending on the event type and operating system.

### Common Fields (all events)

All events include standard DRAKVUF fields such as:
- Timestamp
- Process name
- PID
- TID
- PPID
- User ID (where applicable)

### Running Process Enumeration (startup)

Output at plugin initialization for each running process.

### Windows-Specific Events

#### NtCreateUserProcess

| Field | Type | Description |
|-------|------|-------------|
| Status | Hex | NTSTATUS return code |
| NewProcessHandle | Hex | Handle to the new process |
| NewPid | Number | PID of the new process |
| NewThreadHandle | Hex | Handle to the main thread |
| NewTid | Number | TID of the main thread |
| CommandLine | String | Full command line |
| ImagePathName | String | Path to the executable |
| DllPath | String | DLL search path |
| CWD | String | Current working directory |
| Bitness | Number | Process bitness (32/64) |

#### NtCreateProcessEx

| Field | Type | Description |
|-------|------|-------------|
| Status | Hex | NTSTATUS return code |
| ProcessHandle | Hex | Handle to the new process |
| DesiredAccess | Hex | Requested access mask |
| ObjectAttributes | Hex | Object attributes address |
| ParentProcess | Hex | Parent process handle |
| Flags | Hex | Creation flags |
| SectionHandle | Hex | Section handle |
| DebugPort | Hex | Debug port handle |
| ExceptionPort | Hex | Exception port handle |
| JobMemberLevel | Number | Job member level |
| NewPid | Number | PID of the new process |
| Bitness | Number | Process bitness |

#### NtTerminateProcess

| Field | Type | Description |
|-------|------|-------------|
| ExitPid | Number | PID of terminating process |
| ExitStatus | Hex | Exit status code |
| ExitStatusStr | String | Human-readable exit status |

#### MmCleanProcessAddressSpace

| Field | Type | Description |
|-------|------|-------------|
| ExitPid | Number | PID of process being cleaned |

#### NtOpenProcess

| Field | Type | Description |
|-------|------|-------------|
| ProcessHandle | Hex | Resulting process handle |
| DesiredAccess | Hex | Requested access mask |
| ObjectAttributes | Hex | Object attributes address |
| ClientID | Number | Target process PID |
| ClientName | String | Target process name |

#### NtOpenThread

| Field | Type | Description |
|-------|------|-------------|
| ThreadHandle | Hex | Resulting thread handle |
| DesiredAccess | Hex | Requested access mask |
| ObjectAttributes | Hex | Object attributes address |
| ClientID | Number | Target process PID |
| ClientName | String | Target process name |
| UniqueThread | Number | Target thread ID |

#### NtProtectVirtualMemory

| Field | Type | Description |
|-------|------|-------------|
| ProcessHandle | Hex | Target process handle |
| NewProtectWin32 | String | New protection attributes |

#### NtAdjustPrivilegesToken

| Field | Type | Description |
|-------|------|-------------|
| ProcessHandle | Number | Token handle |
| DisableAll | Number | 1 if disabling all privileges |
| NewState | Array | List of privilege changes |

### Linux-Specific Events

#### execve (begin_new_exec)

| Field | Type | Description |
|-------|------|-------------|
| ThreadName | String | Name of the calling thread |
| CommandLine | String | Full command line arguments |
| ImagePathName | String | Path to the executable |
| ouid | Number | Original UID before exec |
| osuid | Number | Original saved UID before exec |
| oeuid | Number | Original effective UID before exec |
| suid | Number | Saved UID after exec |
| euid | Number | Effective UID after exec |
| Environment | String | Filtered environment variables (comma-separated key=value pairs) |
| interp | String | Interpreter path (if applicable) |
| fdpath | String | File descriptor path (if applicable) |
| FileName | String | Original filename |
| PGID | Number | Process group ID |
| have_execfd | Number | 1 if exec via file descriptor |
| execfd | Number | Exec file descriptor value |
| secureexec | Number | 1 if secure execution mode |

#### do_exit

| Field | Type | Description |
|-------|------|-------------|
| ThreadName | String | Name of the exiting thread |
| ExitStatus | Number | Exit status code |
| ExitStatusStr | String | Human-readable exit status |

#### Signal Delivery (do_send_sig_info)

| Field | Type | Description |
|-------|------|-------------|
| ThreadName | String | Name of the sending thread |
| TargetPID | Number | Target process PID |
| TargetTID | Number | Target thread TID |
| TargetPPID | Number | Target process parent PID |
| TargetProcessName | String | Target process name |
| TargetThreadName | String | Target thread name |
| Signal | Number | Signal number |
| SignalStr | String | Signal name (e.g., SIGTERM, SIGKILL) |

#### kernel_clone

| Field | Type | Description |
|-------|------|-------------|
| Flags | String | Clone flags (e.g., CLONE_VM, CLONE_THREAD) |
| Signal | Number | Exit signal number |
| SignalStr | String | Exit signal name |
| NewPid | Number | PID of the new process/thread |

## Example Output

### Linux execve Event (JSON format)

```json
{
  "Plugin": "procmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 1234,
  "ProcessName": "bash",
  "Method": "begin_new_exec",
  "ThreadName": "bash",
  "CommandLine": "/usr/bin/ls -la /home/user",
  "ImagePathName": "ls",
  "ouid": 1000,
  "osuid": 1000,
  "oeuid": 1000,
  "suid": 1000,
  "euid": 1000,
  "Environment": "PWD=/home/user,OLDPWD=/home",
  "FileName": "/usr/bin/ls",
  "PGID": 1234
}
```

### Linux Signal Event (JSON format)

```json
{
  "Plugin": "procmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 1234,
  "ProcessName": "bash",
  "Method": "do_send_sig_info",
  "ThreadName": "bash",
  "TargetPID": 5678,
  "TargetTID": 5678,
  "TargetPPID": 1234,
  "TargetProcessName": "sleep",
  "TargetThreadName": "sleep",
  "Signal": 15,
  "SignalStr": "SIGTERM"
}
```

### Linux kernel_clone Event (JSON format)

```json
{
  "Plugin": "procmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 1234,
  "ProcessName": "bash",
  "Method": "kernel_clone",
  "Flags": "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID",
  "Signal": 17,
  "SignalStr": "SIGCHLD",
  "NewPid": 5678
}
```

### Windows Process Creation Event (JSON format)

```json
{
  "Plugin": "procmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 1234,
  "ProcessName": "explorer.exe",
  "Method": "NtCreateUserProcess",
  "Status": "0x0",
  "NewProcessHandle": "0x1a4",
  "NewPid": 5678,
  "NewThreadHandle": "0x1a8",
  "NewTid": 5680,
  "CommandLine": "\"C:\\Windows\\System32\\notepad.exe\" test.txt",
  "ImagePathName": "C:\\Windows\\System32\\notepad.exe",
  "DllPath": "C:\\Windows\\System32",
  "CWD": "C:\\Users\\User\\Desktop",
  "Bitness": 64
}
```

### Windows Process Termination Event (JSON format)

```json
{
  "Plugin": "procmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 1234,
  "ProcessName": "explorer.exe",
  "Method": "NtTerminateProcess",
  "ExitPid": 5678,
  "ExitStatus": "0x0",
  "ExitStatusStr": "STATUS_SUCCESS"
}
```
