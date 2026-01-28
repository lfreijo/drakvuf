# IPT Plugin

## Overview

The IPT (Intel Processor Trace) plugin enables hardware-assisted tracing of code execution within virtual machines using Intel Processor Trace technology. This plugin captures detailed execution flow information including branch targets and control flow changes, writing the trace data to binary files that can be decoded using Intel PT decoding tools.

The plugin works by:
1. Enabling Intel Processor Trace on each virtual CPU (vCPU)
2. Capturing raw IPT data into per-vCPU binary stream files
3. Annotating the trace stream with context information (CR3 values, thread IDs, event IDs) using PTWRITE packets
4. Flushing trace data to disk on CR3 changes (context switches) and other DRAKVUF events

## Supported Operating Systems

| Operating System | Supported |
|-----------------|-----------|
| Windows         | Yes       |
| Linux           | Yes       |

## Configuration Options

### Command Line Options

| Option | Argument | Description |
|--------|----------|-------------|
| `--ipt-dir <directory>` | Required | Directory where IPT stream files will be stored. The directory will be created if it does not exist. |
| `--ipt-trace-os` | None | Enable tracing of kernel/ring 0 code execution |
| `--ipt-trace-user` | None | Enable tracing of userspace/ring > 0 code execution |

**Note:** At least one of `--ipt-trace-os` or `--ipt-trace-user` should be specified to capture meaningful traces. The plugin always enables branch tracing and disables RET compression for easier trace reconstruction.

## How to Enable the Plugin

### Build-time Configuration

The plugin can be enabled or disabled at build time using Meson options:

```bash
# Enable the plugin (default)
meson configure -Dplugin-ipt=true

# Disable the plugin
meson configure -Dplugin-ipt=false
```

Additionally, the IPT feature itself can be controlled:

```bash
# Enable IPT support (default)
meson configure -Dipt=true

# Disable IPT support
meson configure -Dipt=false
```

### Runtime Usage

```bash
# Basic usage - trace userspace code
drakvuf -r <rekall_profile> -d <domain> --ipt-dir /path/to/output --ipt-trace-user

# Trace both kernel and userspace
drakvuf -r <rekall_profile> -d <domain> --ipt-dir /path/to/output --ipt-trace-os --ipt-trace-user

# Trace kernel only
drakvuf -r <rekall_profile> -d <domain> --ipt-dir /path/to/output --ipt-trace-os
```

## Output Format

### Output Files

The plugin creates one binary file per vCPU in the specified output directory:

```
<ipt-dir>/ipt_stream_vcpu0
<ipt-dir>/ipt_stream_vcpu1
...
<ipt-dir>/ipt_stream_vcpu<N>
```

The maximum number of vCPUs supported is 16.

### Binary Stream Format

The output files contain raw Intel Processor Trace data interleaved with synthetic PTWRITE packets for annotation. The binary format follows the Intel PT specification and can be decoded using tools like `libipt` or `perf`.

### Annotation Packets

The plugin injects PTWRITE packets into the trace stream to provide context information. Each annotation packet consists of:

- Packet type byte: `0x02`
- Mode byte: `0x32` (8-byte payload, no FUP)
- 8-byte payload: Upper 32 bits contain the command type, lower 32 bits contain the data

| Command | Value | Description |
|---------|-------|-------------|
| `PTW_CURRENT_CR3` | `0xC3000000` | Current CR3 register value (page table base). Data contains the CR3 value truncated to 32 bits. |
| `PTW_CURRENT_TID` | `0x1D000000` | Current thread ID. Data contains the thread ID. |
| `PTW_EVENT_ID` | `0xCC000000` | DRAKVUF event unique identifier. Data contains the event UID. |
| `PTW_ERROR_EMPTY` | `0xBAD10000` | Error indicator: flush was called but no new IPT data was present. |

### Decoding the Output

The binary stream files must be decoded using Intel PT decoder tools. The PTWRITE annotations help correlate trace data with process context and DRAKVUF events.

Example using `libipt`:

```bash
ptdump <ipt-dir>/ipt_stream_vcpu0
```

## Internal Operation

1. **Initialization**: The plugin enables IPT on each vCPU with the following fixed flags:
   - `DRAKVUF_IPT_BRANCH_EN`: Enable branch tracing (always on)
   - `DRAKVUF_IPT_DIS_RETC`: Disable RET compression for easier reconstruction (always on)
   - `DRAKVUF_IPT_TRACE_OS`: Trace ring 0 (optional, via `--ipt-trace-os`)
   - `DRAKVUF_IPT_TRACE_USR`: Trace ring > 0 (optional, via `--ipt-trace-user`)

2. **CR3 Hook**: On every CR3 change (typically a context switch), the plugin:
   - Flushes the current IPT buffer to the output file
   - Annotates the stream with the new CR3 value
   - Annotates the stream with the current thread ID

3. **Catch-all Hook**: On any DRAKVUF event, the plugin:
   - Flushes the current IPT buffer to the output file
   - Annotates the stream with the event's unique ID

4. **Buffer Management**: The plugin tracks the last flushed offset and handles buffer wraparound correctly, ensuring no trace data is lost between events.

## Requirements

- Intel processor with Processor Trace support
- Xen hypervisor with IPT/vmtrace support
- DRAKVUF compiled with IPT support (`-Dipt=true`)
