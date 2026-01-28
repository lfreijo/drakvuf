# ebpfmon Plugin

## Overview

The ebpfmon plugin monitors eBPF (extended Berkeley Packet Filter) system calls in Linux virtual machines. It hooks the `__do_sys_bpf` kernel function to intercept and log all BPF syscall invocations, providing visibility into eBPF program loading, map operations, and attachment activities within the guest VM.

eBPF is a powerful Linux kernel technology that allows running sandboxed programs in kernel space. Monitoring eBPF activity is valuable for security analysis as eBPF can be used for both legitimate purposes (tracing, networking, security) and malicious purposes (rootkits, hiding malicious activity).

## Supported Operating Systems

- **Linux**: Supported (hooks `__do_sys_bpf` syscall)
- **Windows**: Not supported (eBPF is a Linux-specific technology)

## Configuration Options

The ebpfmon plugin does not have additional configuration options beyond the standard DRAKVUF output format settings.

## How to Enable

The plugin is enabled by default. To explicitly enable or disable it during the meson build:

```bash
# Enable (default)
meson setup build -Dplugin-ebpfmon=true

# Disable
meson setup build -Dplugin-ebpfmon=false
```

The plugin requires the `__do_sys_bpf` kernel symbol to be available in the Linux guest. If this symbol is not found, the plugin will log a debug message and remain inactive.

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
| ProcessName | Name of the process making the BPF syscall |
| Method | Always "bpf" (the syscall name) |
| EventUID | Unique event identifier |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| Value | The BPF command being executed (see BPF Commands below) |
| Type | The type associated with the command (map type, program type, or attach type depending on the command). Only present for certain commands. |

### BPF Commands (Value field)

The following BPF commands are tracked:

**Map Operations:**
- `BPF_MAP_CREATE` - Create a new BPF map
- `BPF_MAP_LOOKUP_ELEM` - Look up an element in a map
- `BPF_MAP_UPDATE_ELEM` - Update an element in a map
- `BPF_MAP_DELETE_ELEM` - Delete an element from a map
- `BPF_MAP_GET_NEXT_KEY` - Iterate to next key in a map
- `BPF_MAP_GET_NEXT_ID` - Get next map ID
- `BPF_MAP_GET_FD_BY_ID` - Get map file descriptor by ID
- `BPF_MAP_LOOKUP_AND_DELETE_ELEM` - Atomic lookup and delete
- `BPF_MAP_FREEZE` - Freeze a map (make read-only)
- `BPF_MAP_LOOKUP_BATCH` - Batch lookup operations
- `BPF_MAP_LOOKUP_AND_DELETE_BATCH` - Batch lookup and delete
- `BPF_MAP_UPDATE_BATCH` - Batch update operations
- `BPF_MAP_DELETE_BATCH` - Batch delete operations

**Program Operations:**
- `BPF_PROG_LOAD` - Load a BPF program
- `BPF_PROG_ATTACH` - Attach a BPF program
- `BPF_PROG_DETACH` - Detach a BPF program
- `BPF_PROG_RUN` - Run/test a BPF program
- `BPF_PROG_GET_NEXT_ID` - Get next program ID
- `BPF_PROG_GET_FD_BY_ID` - Get program file descriptor by ID
- `BPF_PROG_QUERY` - Query attached programs
- `BPF_PROG_BIND_MAP` - Bind a map to a program

**Object Operations:**
- `BPF_OBJ_PIN` - Pin object to filesystem
- `BPF_OBJ_GET` - Get pinned object
- `BPF_OBJ_GET_INFO_BY_FD` - Get object info by file descriptor

**Link Operations:**
- `BPF_LINK_CREATE` - Create a BPF link
- `BPF_LINK_UPDATE` - Update a BPF link
- `BPF_LINK_GET_FD_BY_ID` - Get link file descriptor by ID
- `BPF_LINK_GET_NEXT_ID` - Get next link ID
- `BPF_LINK_DETACH` - Detach a BPF link

**BTF (BPF Type Format) Operations:**
- `BPF_BTF_LOAD` - Load BTF data
- `BPF_BTF_GET_FD_BY_ID` - Get BTF file descriptor by ID
- `BPF_BTF_GET_NEXT_ID` - Get next BTF ID

**Other Operations:**
- `BPF_RAW_TRACEPOINT_OPEN` - Open a raw tracepoint
- `BPF_TASK_FD_QUERY` - Query task file descriptor
- `BPF_ENABLE_STATS` - Enable BPF statistics
- `BPF_ITER_CREATE` - Create a BPF iterator

### Type Field Values

The Type field is populated based on the command:

**For BPF_MAP_CREATE** - Map types:
- `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_PROG_ARRAY`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, `BPF_MAP_TYPE_PERCPU_HASH`, `BPF_MAP_TYPE_PERCPU_ARRAY`
- `BPF_MAP_TYPE_STACK_TRACE`, `BPF_MAP_TYPE_CGROUP_ARRAY`, `BPF_MAP_TYPE_LRU_HASH`
- `BPF_MAP_TYPE_RINGBUF`, `BPF_MAP_TYPE_BLOOM_FILTER`, and more

**For BPF_PROG_LOAD** - Program types:
- `BPF_PROG_TYPE_SOCKET_FILTER`, `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`
- `BPF_PROG_TYPE_XDP`, `BPF_PROG_TYPE_PERF_EVENT`, `BPF_PROG_TYPE_CGROUP_SKB`
- `BPF_PROG_TYPE_LSM`, `BPF_PROG_TYPE_TRACING`, and more

**For BPF_PROG_ATTACH/DETACH/QUERY and BPF_LINK_CREATE** - Attach types:
- `BPF_CGROUP_INET_INGRESS`, `BPF_CGROUP_INET_EGRESS`, `BPF_CGROUP_SOCK_OPS`
- `BPF_TRACE_FENTRY`, `BPF_TRACE_FEXIT`, `BPF_LSM_MAC`, `BPF_XDP`, and more

## Example Output

### Default Format

```
[EBPFMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "malware":bpf UID:0 PID:1234 PPID:1 Value:BPF_PROG_LOAD Type:BPF_PROG_TYPE_KPROBE
```

### JSON Format

```json
{"Plugin":"ebpfmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":1,"TID":1234,"UserId":0,"ProcessName":"malware","Method":"bpf","EventUID":"0x123ABC","Value":"BPF_PROG_LOAD","Type":"BPF_PROG_TYPE_KPROBE"}
```

### Key-Value Format

```
ebpfmon Time=1234567890.123456 PID=1234 PPID=1 ProcessName="malware" Method=bpf Value=BPF_PROG_LOAD Type=BPF_PROG_TYPE_KPROBE
```

## Security Considerations

Monitoring eBPF activity can help detect:

1. **Rootkit installation** - Malicious eBPF programs that hide processes, files, or network connections
2. **Kernel-level keyloggers** - eBPF programs attached to input events
3. **Network traffic manipulation** - XDP or TC programs modifying packets
4. **Security tool evasion** - Programs attempting to bypass security monitoring
5. **Privilege escalation attempts** - Exploitation of eBPF vulnerabilities

Events of particular interest:
- `BPF_PROG_LOAD` with types like `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, or `BPF_PROG_TYPE_LSM`
- `BPF_PROG_ATTACH` operations from unexpected processes
- High-privilege processes (UID 0) loading eBPF programs
