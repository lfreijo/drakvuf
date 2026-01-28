# CPUIDMON Plugin

## Overview

The cpuidmon plugin monitors CPUID instruction executions within the guest virtual machine. CPUID is a processor instruction that returns information about the CPU, including vendor identification, processor features, cache information, and hypervisor presence. This plugin intercepts all CPUID instruction executions and logs the leaf/subleaf being queried along with the resulting register values.

Additionally, the plugin provides a **stealth mode** that can hide hypervisor presence from the guest by modifying CPUID responses. This is useful for evading malware that uses CPUID to detect virtualized environments.

## Supported Operating Systems

| OS      | Supported |
|---------|-----------|
| Windows | Yes       |
| Linux   | Yes       |

## Configuration Options

### Stealth Mode (`-s`)

When enabled, stealth mode modifies CPUID responses to hide hypervisor presence:

- **Leaf 1**: Clears bit 31 of ECX (the hypervisor present bit), which indicates to the guest that it is not running in a virtualized environment.

- **Leaves 0x40000000 - 0x40000004**: These are hypervisor-specific CPUID leaves (hypervisor vendor identification and feature leaves). In stealth mode, all output registers (RAX, RBX, RCX, RDX) are zeroed for these leaves.

## How to Enable the Plugin

### Build-time Configuration (Meson)

The plugin is enabled by default. To explicitly enable or disable it during build:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-cpuidmon=true

# Disable the plugin
meson setup build -Dplugin-cpuidmon=false
```

### Runtime Activation

The plugin is activated by default when built. To use stealth mode, pass the `-s` flag:

```bash
drakvuf -r <kernel_profile.json> -d <domain> -s
```

To explicitly disable the plugin at runtime:

```bash
drakvuf -r <kernel_profile.json> -d <domain> -x cpuidmon
```

To explicitly enable the plugin at runtime:

```bash
drakvuf -r <kernel_profile.json> -d <domain> -a cpuidmon
```

## Output Format

The plugin outputs information for each CPUID instruction execution. The output format depends on the global output format setting (`-o` flag).

### Output Fields

| Field    | Type        | Description                                              |
|----------|-------------|----------------------------------------------------------|
| VCPU     | Numeric     | Virtual CPU number that executed the CPUID instruction   |
| CR3      | Numeric     | Control Register 3 value (page directory base address)   |
| Leaf     | Hexadecimal | CPUID leaf (function) number being queried               |
| Subleaf  | Hexadecimal | CPUID subleaf (sub-function) number being queried        |
| RAX      | Hexadecimal | Value returned in RAX register after CPUID execution     |
| RBX      | Hexadecimal | Value returned in RBX register after CPUID execution     |
| RCX      | Hexadecimal | Value returned in RCX register after CPUID execution     |
| RDX      | Hexadecimal | Value returned in RDX register after CPUID execution     |

Additionally, standard DRAKVUF fields are included (timestamp, process name, PID, PPID, TID, user ID, etc.).

## Example Output

### Default Format

```
[CPUIDMON] TIME:1234567890 VCPU:0 CR3:0x1aa000 cpuidmon VCPU:0 CR3:7507968 Leaf:0x1 Subleaf:0x0 RAX:0x306c3 RBX:0x4100800 RCX:0x7ffafbff RDX:0xbfebfbff ProcessName:test.exe PID:1234 PPID:4 TID:5678 UserID:0
```

### JSON Format (`-o json`)

```json
{
  "Plugin": "cpuidmon",
  "TimeStamp": "1234567890",
  "VCPU": 0,
  "CR3": 7507968,
  "ProcessName": "test.exe",
  "PID": 1234,
  "PPID": 4,
  "TID": 5678,
  "UserID": 0,
  "Leaf": "0x1",
  "Subleaf": "0x0",
  "RAX": "0x306c3",
  "RBX": "0x4100800",
  "RCX": "0x7ffafbff",
  "RDX": "0xbfebfbff"
}
```

### Key-Value Format (`-o kv`)

```
cpuidmon TIME:1234567890 VCPU:0 CR3:7507968 Leaf:0x1 Subleaf:0x0 RAX:0x306c3 RBX:0x4100800 RCX:0x7ffafbff RDX:0xbfebfbff ProcessName:test.exe PID:1234 PPID:4 TID:5678 UserID:0
```

### CSV Format (`-o csv`)

```
cpuidmon,1234567890,0,7507968,test.exe,1234,4,5678,0,0x1,0x0,0x306c3,0x4100800,0x7ffafbff,0xbfebfbff
```

## Common CPUID Leaves

| Leaf          | Description                                    |
|---------------|------------------------------------------------|
| 0x0           | Highest function parameter and vendor ID       |
| 0x1           | Processor info and feature bits                |
| 0x2           | Cache and TLB descriptor information           |
| 0x7           | Extended features                              |
| 0x40000000    | Hypervisor vendor leaf                         |
| 0x40000001    | Hypervisor interface identification            |
| 0x80000000    | Extended function CPUID information            |
| 0x80000001    | Extended processor info and feature bits       |
| 0x80000002-4  | Processor brand string                         |

## Use Cases

1. **Malware Analysis**: Detect when malware attempts to identify virtualized environments through CPUID queries.

2. **Anti-Evasion**: Use stealth mode to prevent malware from detecting and evading the analysis environment.

3. **System Profiling**: Monitor which CPUID functions are being queried by applications.

4. **VM Detection Research**: Study techniques used by software to detect virtual machines.
