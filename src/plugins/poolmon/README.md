# Poolmon Plugin

## Overview

The poolmon plugin monitors Windows kernel pool memory allocations by hooking the `ExAllocatePoolWithTag` kernel function. When any component in the monitored Windows virtual machine allocates memory from the kernel pool with a tag, this plugin intercepts the call and logs information about the allocation including the pool tag, pool type, allocation size, and (when known) the source driver and description of the allocation.

Pool tags are 4-byte identifiers used by Windows drivers and kernel components to tag their memory allocations. This plugin includes a built-in database of over 2,200 known Windows pool tags that maps tags to their source drivers and descriptions, enabling identification of what component is making each allocation.

## Supported Operating Systems

- **Windows**: Fully supported (both 32-bit and 64-bit)
- **Linux**: Not supported

## Configuration Options

The poolmon plugin does not have any specific configuration options beyond the standard DRAKVUF output format setting. The output format is controlled globally via the DRAKVUF `-o` command line option.

## How to Enable the Plugin

The poolmon plugin is enabled by default in the DRAKVUF build. It can be controlled via the meson build option:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-poolmon=true

# Disable the plugin
meson setup build -Dplugin-poolmon=false
```

When building with default options, the plugin is automatically included.

## Output Format

The plugin outputs one line per pool allocation event. The output includes standard DRAKVUF fields plus plugin-specific fields.

### Standard Fields (from trap info)

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | CR3 register value (page directory base) of the process |
| Process Name | Name of the process making the allocation |
| SessionID | Windows session ID of the process |
| PID | Process ID |
| PPID | Parent process ID |

### Plugin-Specific Fields

| Field | Description |
|-------|-------------|
| VCPU | Virtual CPU number (also included in plugin output) |
| CR3 | CR3 register value (also included in plugin output) |
| Tag | 4-character pool tag identifying the allocation (e.g., "Proc", "File", "Ntfs") |
| Type | Pool type string (see Pool Types below) |
| Size | Size of the allocation in bytes |
| Source | Source driver/component for known tags (e.g., "ntoskrnl.exe", "ntfs.sys") |
| Description | Human-readable description of what the tag is used for |

### Pool Types

The following pool types may appear in the Type field:

| Pool Type | Description |
|-----------|-------------|
| NonPagedPool | Non-paged pool memory (cannot be paged out) |
| PagedPool | Paged pool memory (can be paged to disk) |
| NonPagedPoolMustSucceed | Non-paged pool that must succeed (deprecated) |
| DontUseThisType | Reserved/deprecated type |
| NonPagedPoolCacheAligned | Cache-aligned non-paged pool |
| PagedPoolCacheAligned | Cache-aligned paged pool |
| NonPagedPoolCacheAlignedMustS | Cache-aligned non-paged pool that must succeed |
| unknown_pool_type | Unrecognized pool type value |

## Example Output

### Default Format

```
[POOLMON] TIME:1234567890.123456 VCPU:0 CR3:0x1aa000 "explorer.exe":ExAllocatePoolWithTag SessionID:1 PID:1234 PPID:456 VCPU:0 CR3:7318528 Tag:"Proc" Type:"NonPagedPool" Size:512 Source:"ntoskrnl.exe" Description:"Process objects"
```

### JSON Format

```json
{"Plugin":"poolmon","TimeStamp":"1234567890.123456","VCPU":0,"CR3":"0x1aa000","ProcessName":"explorer.exe","Method":"ExAllocatePoolWithTag","SessionID":1,"PID":1234,"PPID":456,"VCPU":0,"CR3":7318528,"Tag":"Proc","Type":"NonPagedPool","Size":512,"Source":"ntoskrnl.exe","Description":"Process objects"}
```

### Notes

- The Source and Description fields are only populated when the pool tag is found in the built-in database of known tags. For unknown tags, these fields may be omitted or empty.
- Non-ASCII characters in pool tags are replaced with '?' for safe output.
- The plugin uses a limited trap TTL (time-to-live) as configured by DRAKVUF for performance optimization.
