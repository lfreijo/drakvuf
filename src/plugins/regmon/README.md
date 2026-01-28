# regmon Plugin

## Overview

The `regmon` (Registry Monitor) plugin monitors Windows registry operations by hooking NT system calls related to registry access. It captures and logs registry key creation, opening, deletion, querying, enumeration, and value modification operations. This plugin is useful for monitoring malware behavior, tracking persistence mechanisms, and analyzing how applications interact with the Windows registry.

## Supported Operating Systems

- **Windows only**

The plugin relies on Windows NT kernel functions (`NtCreateKey`, `NtOpenKey`, `NtSetValueKey`, etc.) and Windows-specific data structures (`_OBJECT_ATTRIBUTES`). It does not support Linux.

## Configuration Options

The plugin requires kernel debug symbols to resolve the following structure offsets:

| Structure | Member | Purpose |
|-----------|--------|---------|
| `_OBJECT_ATTRIBUTES` | `ObjectName` | To extract registry key names |
| `_OBJECT_ATTRIBUTES` | `RootDirectory` | To resolve the parent key handle |

No additional configuration files or profiles are required beyond the standard Windows kernel profile.

## How to Enable the Plugin

The plugin is enabled by default. To explicitly enable or disable it during build configuration with Meson:

```bash
# Enable (default)
meson setup build -Dplugin-regmon=true

# Disable
meson setup build -Dplugin-regmon=false
```

## Monitored Functions

The plugin hooks the following Windows NT system calls:

| Function | Description |
|----------|-------------|
| `NtCreateKey` | Creates a new registry key or opens an existing one |
| `NtCreateKeyTransacted` | Creates/opens a registry key within a transaction |
| `NtOpenKey` | Opens an existing registry key |
| `NtOpenKeyEx` | Opens a registry key with additional options |
| `NtOpenKeyTransacted` | Opens a registry key within a transaction |
| `NtOpenKeyTransactedEx` | Opens a registry key within a transaction with options |
| `NtDeleteKey` | Deletes a registry key |
| `NtSetValueKey` | Sets the data for a value of a registry key |
| `NtDeleteValueKey` | Deletes a value from a registry key |
| `NtQueryKey` | Retrieves information about a registry key |
| `NtQueryValueKey` | Retrieves information about a value of a registry key |
| `NtQueryMultipleValueKey` | Retrieves information about multiple values |
| `NtEnumerateKey` | Enumerates subkeys of a registry key |
| `NtEnumerateValueKey` | Enumerates values of a registry key |

## Output Format

### Common Fields

All output records include standard DRAKVUF fields:

| Field | Description |
|-------|-------------|
| Plugin | Always "regmon" |
| TimeStamp | Event timestamp |
| PID | Process ID |
| PPID | Parent process ID |
| TID | Thread ID |
| UserName | User context |
| UserId | User ID |
| ProcessName | Name of the process making the call |
| Method | The hooked function name |

### Plugin-Specific Fields

| Field | Description | Present When |
|-------|-------------|--------------|
| `Key` | Full registry key path | Always |
| `ValueName` | Name of the registry value (or "(Default)" for default values) | Value operations only |
| `Value` | Data being written to the registry | `NtSetValueKey` only |
| `RegOptions` | Registry operation flags | `NtCreateKey*` and `NtOpenKeyEx*` operations |

### Registry Options Flags

The `RegOptions` field may contain the following flags:

| Flag | Value | Description |
|------|-------|-------------|
| `REG_OPTION_VOLATILE` | 0x00000001 | Key is not preserved on reboot |
| `REG_OPTION_CREATE_LINK` | 0x00000002 | Key is a symbolic link |
| `REG_OPTION_BACKUP_RESTORE` | 0x00000004 | Open for backup/restore |
| `REG_OPTION_OPEN_LINK` | 0x00000008 | Open a symbolic link |
| `REG_OPTION_DONT_VIRTUALIZE` | 0x00000010 | Disable registry virtualization |

### Supported Registry Value Types

When logging `NtSetValueKey` operations, the plugin decodes and formats the value data based on its type:

| Type | Value | Output Format |
|------|-------|---------------|
| `REG_SZ` | 1 | Unicode string |
| `REG_EXPAND_SZ` | 2 | Unicode string (with environment variables) |
| `REG_LINK` | 6 | Unicode string (symbolic link) |
| `REG_MULTI_SZ` | 7 | Comma-separated quoted strings (e.g., `'value1','value2'`) |
| `REG_BINARY` | 3 | Hexadecimal byte sequence |
| `REG_DWORD` | 4 | Hexadecimal byte sequence |
| `REG_DWORD_BIG_ENDIAN` | 5 | Hexadecimal byte sequence |
| `REG_QWORD` | 11 | Hexadecimal byte sequence |
| Other types | - | Hexadecimal byte sequence |

## Example Output

### JSON Format

#### NtCreateKey - Creating a registry key

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtCreateKey", "Key": "\\REGISTRY\\USER\\S-1-5-21-123456789\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "RegOptions": "REG_OPTION_VOLATILE"}
```

#### NtSetValueKey - Setting a registry value

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtSetValueKey", "Key": "\\REGISTRY\\USER\\S-1-5-21-123456789\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "ValueName": "Malware", "Value": "C:\\Users\\Public\\malware.exe"}
```

#### NtDeleteKey - Deleting a registry key

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtDeleteKey", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\TempKey"}
```

#### NtQueryValueKey - Querying a registry value

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtQueryValueKey", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ValueName": "ProductName"}
```

#### NtOpenKeyEx - Opening a key with options

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtOpenKeyEx", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "RegOptions": "REG_OPTION_OPEN_LINK"}
```

#### NtQueryMultipleValueKey - Querying multiple values

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtQueryMultipleValueKey", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ValueName": "ProgramFilesDir,CommonFilesDir"}
```

#### NtSetValueKey - Setting a REG_MULTI_SZ value

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtSetValueKey", "Key": "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ServiceGroupOrder", "ValueName": "List", "Value": "'Group1','Group2','Group3'"}
```

#### NtSetValueKey - Setting a REG_BINARY value

```json
{"Plugin": "regmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "NtSetValueKey", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Test", "ValueName": "BinaryData", "Value": "01 02 03 04 05 06 07 08"}
```
