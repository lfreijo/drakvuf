# Exception Monitor Plugin (exmon)

## Overview

The exmon (Exception Monitor) plugin monitors Windows kernel exception dispatching by hooking the `KiDispatchException` function in `ntoskrnl.exe`. When an exception occurs in the guest operating system, this plugin captures detailed information about the exception, including the exception code, register state at the time of the exception, and process context.

This plugin is useful for:
- Detecting and analyzing application crashes
- Monitoring exception-based anti-debugging techniques
- Tracking software errors and fault conditions
- Malware analysis (monitoring exceptions raised during execution)

## Supported Operating Systems

**Windows only** - This plugin hooks the Windows kernel function `KiDispatchException` and reads the Windows `_KTRAP_FRAME` structure. It supports both:
- 32-bit Windows (IA-32)
- 64-bit Windows (x86-64)

Linux is not supported by this plugin.

## Configuration Options

This plugin does not have any runtime configuration options. It automatically detects the guest architecture (32-bit or 64-bit) and adjusts its behavior accordingly.

## How to Enable the Plugin

The exmon plugin is enabled by default. It can be controlled via the meson build option:

```bash
# Enable (default)
meson setup build -Dplugin-exmon=true

# Disable
meson setup build -Dplugin-exmon=false
```

## Output Format

The plugin outputs information in the configured DRAKVUF output format (default, CSV, JSON, or key-value). The output fields differ slightly between 32-bit and 64-bit guests.

### Common Fields

| Field | Description |
|-------|-------------|
| Plugin | Always "exmon" |
| TimeStamp | Timestamp when the exception was captured |
| ExceptionRecord | Memory address of the EXCEPTION_RECORD structure |
| ExceptionCode | The Windows exception code (e.g., 0xc0000005 for access violation) |
| FirstChance | 1 if this is a first-chance exception, 0 if second-chance |
| Name | Process name (only present for user-mode exceptions) |

### 32-bit Specific Fields

| Field | Description |
|-------|-------------|
| RSP | Stack pointer at time of hook |
| EIP | Instruction pointer from trap frame |
| EAX | General purpose register from trap frame |
| EBX | General purpose register from trap frame |
| ECX | General purpose register from trap frame |
| EDX | General purpose register from trap frame |
| EDI | General purpose register from trap frame |
| ESI | General purpose register from trap frame |
| EBP | Base pointer from trap frame |
| ESP | Hardware stack pointer from trap frame |

### 64-bit Specific Fields

| Field | Description |
|-------|-------------|
| RSP | Stack pointer (appears twice: once for hook context, once from trap frame) |
| RIP | Instruction pointer from trap frame |
| RAX | General purpose register from trap frame |
| RBX | General purpose register from trap frame |
| RCX | General purpose register from trap frame |
| RDX | General purpose register from trap frame |
| RDI | General purpose register from trap frame |
| RSI | General purpose register from trap frame |
| RBP | Base pointer from trap frame |
| R8-R11 | Extended registers from trap frame |

### Exception Codes

Common Windows exception codes you may encounter:

| Code | Name |
|------|------|
| 0xc0000005 | STATUS_ACCESS_VIOLATION |
| 0xc0000094 | STATUS_INTEGER_DIVIDE_BY_ZERO |
| 0xc0000096 | STATUS_PRIVILEGED_INSTRUCTION |
| 0xc000001d | STATUS_ILLEGAL_INSTRUCTION |
| 0x80000003 | STATUS_BREAKPOINT |
| 0x80000004 | STATUS_SINGLE_STEP |

## Example Output

### JSON Format (64-bit)

```json
{
  "Plugin": "exmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1a2000",
  "RSP": 18446735277665824768,
  "ExceptionRecord": "0xfffff80012345678",
  "ExceptionCode": "0xc0000005",
  "FirstChance": 1,
  "RIP": "0x7ff612340000",
  "RAX": "0x0",
  "RBX": "0x7ff612345000",
  "RCX": "0x1234",
  "RDX": "0x0",
  "RDI": "0x0",
  "RSI": "0x0",
  "RBP": "0x7fff1234abc0",
  "RSP": "0x7fff1234ab80",
  "R8": "0x0",
  "R9": "0x1",
  "R10": "0x0",
  "R11": "0x246",
  "Name": "malware.exe"
}
```

### Key-Value Format (32-bit)

```
exmon Time=1234567890.123456,RSP=0x80123456,ExceptionRecord=0x80234567,ExceptionCode=0xc0000005,FirstChance=1,EIP=0x401000,EAX=0x0,EBX=0x7ffdf000,ECX=0x12345678,EDX=0x0,EDI=0x0,ESI=0x0,EBP=0x12ff80,ESP=0x12ff60,PID=1234,PPID=456,Name="notepad.exe"
```

### Default Format (64-bit)

```
[EXMON] TIME:1234567890.123456 EXCEPTION_RECORD: 0xfffff80012345678 EXCEPTION_CODE: 0xc0000005 FIRST_CHANCE: 1 RIP: 0x7ff612340000 RAX: 0x0 RBX: 0x7ff612345000 RCX: 0x1234 RDX: 0x0 RSP: 0x7fff1234ab80 RBP: 0x7fff1234abc0 RSI: 0x0 RDI: 0x0 R8: 0x0 R9: 0x1 R10: 0x0 R11: 0x246
```
