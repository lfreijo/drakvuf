# DRAKVUF Plugins Overview

This document provides a high-level overview of all DRAKVUF analysis plugins. Each plugin monitors specific aspects of guest virtual machine behavior for malware analysis, security research, and forensics.

## Table of Contents

- [Global Required Flags](#global-required-flags)
- [Process and Execution Monitoring](#process-and-execution-monitoring)
- [System Call Monitoring](#system-call-monitoring)
- [File System Monitoring](#file-system-monitoring)
- [Network Monitoring](#network-monitoring)
- [Memory Monitoring](#memory-monitoring)
- [Windows-Specific Monitoring](#windows-specific-monitoring)
- [Linux-Specific Monitoring](#linux-specific-monitoring)
- [Security and Exploit Detection](#security-and-exploit-detection)
- [Debugging and Analysis](#debugging-and-analysis)
- [Anti-Analysis Detection](#anti-analysis-detection)
- [Extraction and Dumping](#extraction-and-dumping)
- [Utility Plugins](#utility-plugins)

---

## Global Required Flags

All DRAKVUF plugins require these base flags:

| Flag | Description |
|------|-------------|
| `-r, --json-kernel <path>` | **Required.** Path to the kernel JSON debug profile (rekall/volatility3 ISF) |
| `-d <domain>` | **Required.** Xen domain name or ID to introspect |

Common optional flags:

| Flag | Description |
|------|-------------|
| `-o <format>` | Output format: `default`, `json`, `csv`, or `kv` |
| `-w, --json-wow <path>` | JSON profile for WoW64 ntdll.dll (32-bit processes on 64-bit Windows) |
| `-W, --json-win32k <path>` | JSON profile for win32k.sys (required by many Windows GUI-related plugins) |

---

## Process and Execution Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [procmon](src/plugins/procmon/README.md) | Win/Linux | None | Monitors process creation, termination, handle operations, and signal delivery |
| [envmon](src/plugins/envmon/README.md) | Windows | None | Captures environment variables, current directory, and command line for new processes |
| [crashmon](src/plugins/crashmon/README.md) | Windows | None | Detects unhandled exceptions and process crashes |
| [librarymon](src/plugins/librarymon/README.md) | Windows | `--json-ntdll <path>` | Monitors DLL loading and unloading |
| [delaymon](src/plugins/delaymon/README.md) | Windows | None | Tracks time-delay function calls (Sleep, NtDelayExecution) |

---

## System Call Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [syscalls](src/plugins/syscalls/README.md) | Win/Linux | Optional: `-W` for win32k syscalls | Comprehensive syscall monitoring with argument parsing |
| [apimon](src/plugins/apimon/README.md) | Windows | `--dll-hooks-list <path>` | Usermode API hook monitoring for DLL function calls |
| [ssdtmon](src/plugins/ssdtmon/README.md) | Windows | Optional: `-W` for SSDT Shadow | Monitors SSDT modifications |

---

## File System Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [filetracer](src/plugins/filetracer/README.md) | Win/Linux | Optional: `--json-ole32` for rename tracking | Monitors all file operations |
| [filedelete](src/plugins/filedelete/README.md) | Windows | None | Captures files being deleted |
| [fileextractor](src/plugins/fileextractor/README.md) | Windows | `--fileextractor-dump-folder <dir>` | Extracts files written by monitored processes |
| [linkmon](src/plugins/linkmon/README.md) | Windows | None | Monitors symbolic link creation |

---

## Network Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [socketmon](src/plugins/socketmon/README.md) | Windows | `-T, --json-tcpip <path>` | Monitors TCP/UDP socket operations and DNS queries |
| [unixsocketmon](src/plugins/unixsocketmon/README.md) | Linux | Optional: `--unixsocketmon-max-size-print <n>` | Monitors Unix domain socket operations |

---

## Memory Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [memdump](src/plugins/memdump/README.md) | Windows | `--memdump-dir <dir>` (to save dumps) | Dumps memory regions with configurable triggers |
| [memaccessmon](src/plugins/memaccessmon/README.md) | Win/Linux | None | Monitors cross-process memory read/write operations |
| [poolmon](src/plugins/poolmon/README.md) | Windows | None | Monitors kernel pool allocations |
| [spraymon](src/plugins/spraymon/README.md) | Windows | `-W, --json-win32k <path>` | Detects heap spray attacks |
| [codemon](src/plugins/codemon/README.md) | Windows | None | Monitors executable memory pages |

**memdump optional flags:**
- `--json-clr <path>` - .NET 4.x assembly hooking
- `--json-mscorwks <path>` - .NET 2.x/3.x assembly hooking
- `--memdump-disable-*` flags to disable specific hooks

---

## Windows-Specific Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [regmon](src/plugins/regmon/README.md) | Windows | None | Monitors Windows registry operations |
| [objmon](src/plugins/objmon/README.md) | Windows | None | Monitors object manager operations |
| [clipboardmon](src/plugins/clipboardmon/README.md) | Windows | None | Monitors clipboard access and data |
| [windowmon](src/plugins/windowmon/README.md) | Windows | `-W, --json-win32k <path>` | Monitors window operations (FindWindow) |
| [wmimon](src/plugins/wmimon/README.md) | Windows | `--json-ole32 <path>` (Win7) or `--json-combase <path>` (Win8+) | Monitors WMI calls |
| [rpcmon](src/plugins/rpcmon/README.md) | Windows | None | Monitors RPC operations |
| [callbackmon](src/plugins/callbackmon/README.md) | Windows | Optional: `--json-netio`, `--json-ndis` | Monitors kernel callback registrations |
| [etwmon](src/plugins/etwmon/README.md) | Windows | None | Monitors ETW provider operations |
| [tlsmon](src/plugins/tlsmon/README.md) | Windows | None | Extracts TLS session keys |

**wmimon additional flags (64-bit guests):**
- `--json-wow-ole32 <path>` - SysWOW64 ole32.dll profile

---

## Linux-Specific Monitoring

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [ebpfmon](src/plugins/ebpfmon/README.md) | Linux | None | Monitors eBPF program loading |
| [ptracemon](src/plugins/ptracemon/README.md) | Linux | None | Monitors ptrace operations |

---

## Security and Exploit Detection

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [exploitmon](src/plugins/exploitmon/README.md) | Windows | None | Detects exploitation techniques |
| [rootkitmon](src/plugins/rootkitmon/README.md) | Windows | Optional: `--json-fwpkclnt`, `--json-fltmgr`, `--json-ci` | Detects rootkit techniques |
| [dkommon](src/plugins/dkommon/README.md) | Windows | Optional: `--json-services <path>` | Detects DKOM attacks |
| [exmon](src/plugins/exmon/README.md) | Windows | None | Monitors CPU exceptions |

**rootkitmon optional profiles for enhanced detection:**
- `--json-fwpkclnt <path>` - WFP callout monitoring
- `--json-fltmgr <path>` - Filesystem filter callback monitoring
- `--json-ci <path>` - Code integrity checks (Windows 8.1+)

---

## Debugging and Analysis

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [debugmon](src/plugins/debugmon/README.md) | Windows | None | Monitors debug-related operations |
| [bsodmon](src/plugins/bsodmon/README.md) | Windows | Optional: `--crashdump-dir <dir>` | Captures BSOD events |
| [cpuidmon](src/plugins/cpuidmon/README.md) | Win/Linux | None | Monitors CPUID instruction execution |
| [rebootmon](src/plugins/rebootmon/README.md) | Linux | None | Detects system reboot attempts |
| [ipt](src/plugins/ipt/README.md) | Win/Linux | `--ipt-dir <dir>` + `--ipt-trace-os` and/or `--ipt-trace-user` | Intel Processor Trace integration |

---

## Anti-Analysis Detection

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [hidevm](src/plugins/hidevm/README.md) | Windows | Optional: `--hidevm-delay <seconds>` | Hides VM artifacts from malware |
| [hidsim](src/plugins/hidsim/README.md) | Windows | See options below | Simulates human input device activity |

**hidsim options:**
- `--hid-template <path>` - Pre-recorded HID event template
- `--hid-monitor-gui` - Auto-click detected buttons (requires `-W`)
- `--hid-random-clicks` - Random click injection

---

## Extraction and Dumping

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [procdump](src/plugins/procdump/README.md) | Windows | `--procdump-dir <dir>` | Dumps process memory on termination |
| [procdump2](src/plugins/procdump2/README.md) | Windows | `--procdump2-dir <dir>` | Enhanced process dumping |

**procdump optional flags:**
- `--compress-procdumps` - Enable gzip compression

---

## Utility Plugins

| Plugin | OS | Required Flags | Description |
|--------|-----|----------------|-------------|
| [libhooktest](src/plugins/libhooktest/README.md) | Windows | None | Testing utility for libhook |

---

## Plugin Architecture

All DRAKVUF plugins share common characteristics:

### Base Classes
- **`plugin`** - Basic plugin interface (`src/plugins/plugins.h`)
- **`pluginex`** - Extended plugin interface with libhook support (`src/plugins/plugins_ex.h`)

### Output Formats
All plugins support multiple output formats:
- **default** - Human-readable text format
- **json** - JSON format for machine parsing
- **csv** - Comma-separated values
- **kv** - Key-value pairs

### Enabling/Disabling Plugins

Plugins are controlled via Meson build options:

```bash
# Enable a plugin
meson setup build -Dplugin-<name>=true

# Disable a plugin
meson setup build -Dplugin-<name>=false

# Example: Disable syscalls plugin
meson setup build -Dplugin-syscalls=false
```

At runtime, use `-a` to enable and `-x` to disable plugins:

```bash
# Enable specific plugins
drakvuf -r kernel.json -d vm -a procmon -a filetracer

# Disable specific plugins
drakvuf -r kernel.json -d vm -x syscalls
```

---

## Complete Flag Reference

### JSON Profile Flags

| Flag | Profile For | Used By |
|------|-------------|---------|
| `-r, --json-kernel` | ntoskrnl.exe / vmlinux | All plugins (required) |
| `-w, --json-wow` | WoW64 ntdll.dll | 32-bit process support |
| `-W, --json-win32k` | win32k.sys | windowmon, spraymon, hidsim, syscalls |
| `-T, --json-tcpip` | tcpip.sys | socketmon |
| `--json-ntdll` | ntdll.dll | librarymon |
| `--json-ole32` | ole32.dll | wmimon, filetracer |
| `--json-wow-ole32` | SysWOW64/ole32.dll | wmimon (64-bit) |
| `--json-combase` | combase.dll | wmimon (Win8+) |
| `--json-clr` | clr.dll | memdump (.NET 4.x) |
| `--json-mscorwks` | mscorwks.dll | memdump (.NET 2.x/3.x) |
| `--json-fwpkclnt` | fwpkclnt.sys | rootkitmon |
| `--json-fltmgr` | fltmgr.sys | rootkitmon |
| `--json-ci` | ci.dll | rootkitmon |
| `--json-netio` | netio.sys | callbackmon |
| `--json-ndis` | ndis.sys | callbackmon |
| `--json-services` | services.exe | dkommon |
| `--json-hal` | hal.dll | Various |
| `--json-kernel32` | kernel32.dll | Various |
| `--json-kernelbase` | kernelbase.dll | Various |
| `--json-sspicli` | sspicli.dll | Various |
| `--json-iphlpapi` | iphlpapi.dll | Various |
| `--json-mpr` | mpr.dll | Various |

### Directory Flags

| Flag | Used By | Description |
|------|---------|-------------|
| `--memdump-dir <dir>` | memdump | Memory dump output directory |
| `--procdump-dir <dir>` | procdump | Process dump output directory |
| `--procdump2-dir <dir>` | procdump2 | Process dump output directory |
| `--fileextractor-dump-folder <dir>` | fileextractor | Extracted files output directory |
| `--crashdump-dir <dir>` | bsodmon | BSOD crash dump directory |
| `--ipt-dir <dir>` | ipt | IPT trace output directory |

### Configuration Flags

| Flag | Used By | Description |
|------|---------|-------------|
| `--dll-hooks-list <file>` | apimon, memdump | List of DLL functions to hook |
| `--hid-template <file>` | hidsim | Pre-recorded HID events file |
| `--syscalls-filter <file>` | syscalls | Filter specific syscalls to monitor |

---

## Quick Reference by Use Case

### Malware Analysis
Essential plugins for malware analysis:
- `procmon` - Process behavior
- `syscalls` - System call activity
- `filetracer` - File operations
- `regmon` - Registry changes (Windows)
- `socketmon` - Network activity (requires `-T`)
- `apimon` - API calls (requires `--dll-hooks-list`)
- `exploitmon` - Exploit detection

### Forensics and Incident Response
- `fileextractor` - Extract written files (requires `--fileextractor-dump-folder`)
- `filedelete` - Recover deleted files
- `procdump2` - Dump process memory (requires `--procdump2-dir`)
- `memdump` - Memory region extraction (requires `--memdump-dir`)
- `tlsmon` - TLS key extraction

### Rootkit and Kernel Threat Detection
- `rootkitmon` - Rootkit techniques (enhanced with `--json-fwpkclnt`, `--json-fltmgr`, `--json-ci`)
- `dkommon` - DKOM attacks (enhanced with `--json-services`)
- `ssdtmon` - SSDT hooks (enhanced with `-W`)
- `callbackmon` - Kernel callbacks (enhanced with `--json-netio`, `--json-ndis`)

### Anti-Sandbox Evasion Research
- `hidevm` - Hide VM presence
- `hidsim` - Simulate user activity
- `delaymon` - Track timing attacks
- `cpuidmon` - CPUID-based detection

---

## Example Command Lines

### Basic Windows Malware Analysis
```bash
drakvuf -r /path/to/windows.json -d vm_domain -o json
```

### Full Windows Analysis with Network and API Monitoring
```bash
drakvuf -r /path/to/windows.json -d vm_domain -o json \
    -T /path/to/tcpip.json \
    --dll-hooks-list /path/to/hooks.txt \
    --memdump-dir /tmp/memdumps \
    --procdump-dir /tmp/procdumps
```

### Windows with GUI Plugin Support
```bash
drakvuf -r /path/to/windows.json -d vm_domain -o json \
    -W /path/to/win32k.json \
    -w /path/to/wow64.json
```

### Linux Guest Analysis
```bash
drakvuf -r /path/to/linux.json -d vm_domain -o json
```

---

## Further Information

- [DRAKVUF GitHub Repository](https://github.com/tklengyel/drakvuf)
- [LibVMI Documentation](https://libvmi.com/)
- [Xen Project](https://xenproject.org/)
