# ptracemon Plugin

## Overview

The ptracemon plugin monitors the `ptrace` system call in Linux virtual machines. It hooks the `__x64_sys_ptrace` kernel function to intercept and log all ptrace invocations, providing visibility into process tracing and debugging activities within the guest VM.

The `ptrace` system call is commonly used for:
- Debugging processes (e.g., by GDB, strace)
- Process injection and code injection attacks
- Anti-debugging detection by malware
- Process manipulation and memory inspection

Monitoring ptrace activity is valuable for security analysis as it can indicate both legitimate debugging operations and malicious activities such as process injection, credential theft, or anti-analysis techniques.

## Supported Operating Systems

- **Linux**: Supported (hooks `__x64_sys_ptrace` syscall on x86_64 architecture)
- **Windows**: Not supported (ptrace is a Linux/Unix-specific system call)

## Configuration Options

The ptracemon plugin does not have additional configuration options beyond the standard DRAKVUF output format settings.

## How to Enable

The plugin is enabled by default. To explicitly enable or disable it during the meson build:

```bash
# Enable (default)
meson setup build -Dplugin-ptracemon=true

# Disable
meson setup build -Dplugin-ptracemon=false
```

The plugin requires:
- The `__x64_sys_ptrace` kernel symbol to be available in the Linux guest
- The `pt_regs` structure offsets to be resolvable from the kernel debug symbols

If these requirements are not met, the plugin will log a debug message and remain inactive.

## Output Format

### Standard Fields

All output includes the standard DRAKVUF trap information fields:

| Field | Description |
|-------|-------------|
| TimeStamp | Event timestamp (seconds.microseconds) |
| PID | Process ID of the calling process |
| PPID | Parent process ID |
| TID | Thread ID |
| UserId/UID | User ID of the process |
| ProcessName | Name of the process making the ptrace syscall |
| Method | Always "ptrace" (the syscall name) |
| EventUID | Unique event identifier |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| Type | The ptrace request type being executed (see Ptrace Request Types below) |
| TargetPID | The process ID of the target process being traced |
| TargetProcessName | The name of the target process being traced |

### Ptrace Request Types (Type field)

The following ptrace request types are tracked:

**Tracing Control:**
- `PTRACE_TRACEME` (0) - Allow parent to trace this process
- `PTRACE_ATTACH` (16) - Attach to a process
- `PTRACE_DETACH` (17) - Detach from a traced process
- `PTRACE_SEIZE` (0x4206) - Attach without stopping the tracee
- `PTRACE_INTERRUPT` (0x4207) - Stop a seized tracee
- `PTRACE_LISTEN` (0x4208) - Listen for ptrace events

**Memory Access:**
- `PTRACE_PEEKTEXT` (1) - Read word from text segment
- `PTRACE_PEEKDATA` (2) - Read word from data segment
- `PTRACE_PEEKUSER` (3) - Read word from user area
- `PTRACE_POKETEXT` (4) - Write word to text segment
- `PTRACE_POKEDATA` (5) - Write word to data segment
- `PTRACE_POKEUSER` (6) - Write word to user area

**Execution Control:**
- `PTRACE_CONT` (7) - Continue execution
- `PTRACE_KILL` (8) - Kill the traced process
- `PTRACE_SINGLESTEP` (9) - Execute single instruction
- `PTRACE_SINGLEBLOCK` (33) - Execute single basic block
- `PTRACE_SYSCALL` (24) - Continue and stop at next syscall
- `PTRACE_SYSEMU` (31) - Continue with syscall emulation
- `PTRACE_SYSEMU_SINGLESTEP` (32) - Single-step with syscall emulation

**Register Access:**
- `PTRACE_GETREGS` (12) - Get general-purpose registers
- `PTRACE_SETREGS` (13) - Set general-purpose registers
- `PTRACE_GETFPREGS` (14) - Get floating-point registers
- `PTRACE_SETFPREGS` (15) - Set floating-point registers
- `PTRACE_GETFPXREGS` (18) - Get extended floating-point registers
- `PTRACE_SETFPXREGS` (19) - Set extended floating-point registers
- `PTRACE_GETREGSET` (0x4204) - Get register set
- `PTRACE_SETREGSET` (0x4205) - Set register set

**Options and Information:**
- `PTRACE_SETOPTIONS` (0x4200) - Set ptrace options
- `PTRACE_OLDSETOPTIONS` (21) - Old set options interface
- `PTRACE_GETEVENTMSG` (0x4201) - Get ptrace event message
- `PTRACE_GETSIGINFO` (0x4202) - Get signal information
- `PTRACE_SETSIGINFO` (0x4203) - Set signal information
- `PTRACE_PEEKSIGINFO` (0x4209) - Peek at pending signals
- `PTRACE_GETSIGMASK` (0x420a) - Get signal mask
- `PTRACE_SETSIGMASK` (0x420b) - Set signal mask
- `PTRACE_GET_SYSCALL_INFO` (0x420e) - Get syscall information

**Thread Area:**
- `PTRACE_GET_THREAD_AREA` (25) - Get thread-local storage
- `PTRACE_SET_THREAD_AREA` (26) - Set thread-local storage
- `PTRACE_ARCH_PRCTL` (30) - Architecture-specific prctl

**Seccomp:**
- `PTRACE_SECCOMP_GET_FILTER` (0x420c) - Get seccomp filter
- `PTRACE_SECCOMP_GET_METADATA` (0x420d) - Get seccomp metadata

## Example Output

### Default Format

```
[PTRACEMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "gdb":ptrace UID:1000 PID:5678 PPID:5600 Type:PTRACE_ATTACH TargetPID:1234 TargetProcessName:"target_app"
```

### JSON Format

```json
{
  "Plugin": "ptracemon",
  "TimeStamp": "1234567890.123456",
  "PID": 5678,
  "PPID": 5600,
  "TID": 5678,
  "UserId": 1000,
  "ProcessName": "gdb",
  "Method": "ptrace",
  "EventUID": "0x123ABC",
  "Type": "PTRACE_ATTACH",
  "TargetPID": 1234,
  "TargetProcessName": "target_app"
}
```

### Key-Value Format

```
ptracemon Time=1234567890.123456 PID=5678 PPID=5600 ProcessName="gdb" Method=ptrace Type=PTRACE_ATTACH TargetPID=1234 TargetProcessName="target_app"
```

## Security Considerations

Monitoring ptrace activity can help detect:

1. **Process injection attacks** - `PTRACE_ATTACH` followed by `PTRACE_POKETEXT`/`PTRACE_POKEDATA` to inject code into a running process
2. **Credential theft** - Attaching to processes that handle credentials (ssh-agent, gpg-agent, browsers)
3. **Anti-debugging techniques** - Malware using `PTRACE_TRACEME` to prevent debugger attachment
4. **Debugger detection** - Processes checking if they are being traced
5. **Privilege escalation** - Tracing setuid/setgid processes

Events of particular interest:
- `PTRACE_ATTACH` or `PTRACE_SEIZE` from unexpected processes
- `PTRACE_POKETEXT`/`PTRACE_POKEDATA` operations indicating memory modification
- `PTRACE_TRACEME` from processes that normally should not use it
- Any ptrace activity targeting security-sensitive processes
