# envmon Plugin

## Overview

The `envmon` (Environment Monitor) plugin monitors Windows API calls related to environment and system information discovery. It intercepts calls to various Windows DLLs that retrieve computer names, user names, network adapter information, and device definitions. This plugin is useful for detecting reconnaissance activities by malware or analyzing how applications query system information.

## Supported Operating Systems

- **Windows only** (Windows 8 and later for full functionality; Windows 7 supported with reduced features)

The plugin relies on Windows-specific DLLs and does not support Linux.

## Configuration Options

The plugin requires JSON debug info profiles for the following Windows DLLs:

| Profile Option | DLL | Required |
|----------------|-----|----------|
| `sspicli_profile` | sspicli.dll | Yes |
| `kernel32_profile` | kernel32.dll | Yes |
| `kernelbase_profile` | KernelBase.dll | Yes |
| `wow_kernel32_profile` | SysWOW64/kernel32.dll | Yes (64-bit systems only) |
| `iphlpapi_profile` | iphlpapi.dll | Yes |
| `mpr_profile` | mpr.dll | Yes |

## How to Enable the Plugin

The plugin is enabled by default. To explicitly enable or disable it during build configuration with Meson:

```bash
# Enable (default)
meson setup build -Dplugin-envmon=true

# Disable
meson setup build -Dplugin-envmon=false
```

## Monitored Functions

The plugin hooks the following Windows API functions:

| Function | DLL | Description |
|----------|-----|-------------|
| `SspipGetUserName` | sspicli.dll | Retrieves the user name in various formats |
| `GetComputerNameW` | kernel32.dll | Retrieves the NetBIOS name of the local computer |
| `GetComputerNameExW` | KernelBase.dll | Retrieves the computer name in a specified format |
| `IsNativeVhdBoot` | kernel32.dll | Checks if Windows booted from a VHD (Windows 8+) |
| `DefineDosDeviceW` | KernelBase.dll | Defines, redefines, or deletes MS-DOS device names |
| `GetAdaptersAddresses` | iphlpapi.dll | Retrieves network adapter addresses |
| `WNetGetProviderNameW` | mpr.dll | Retrieves the provider name for a network type |

## Output Format

### Common Fields

All output records include standard DRAKVUF fields:

| Field | Description |
|-------|-------------|
| Plugin | Always "envmon" |
| TimeStamp | Event timestamp |
| PID | Process ID |
| PPID | Parent process ID |
| TID | Thread ID |
| UserName | User context |
| UserId | User ID |
| ProcessName | Name of the process making the call |
| Method | The hooked function name |

### Function-Specific Fields

#### SspipGetUserName

| Field | Description |
|-------|-------------|
| `ExtendedNameFormat` | Numeric value of the requested name format |
| `ExtendedNameFormatStr` | String representation of the name format |

Possible `ExtendedNameFormatStr` values:
- `NameUnknown` (0)
- `NameFullyQualifiedDN` (1)
- `NameSamCompatible` (2)
- `NameDisplay` (3)
- `NameUniqueId` (6)
- `NameCanonical` (7)
- `NameUserPrincipal` (8)
- `NameCanonicalEx` (9)
- `NameServicePrincipal` (10)
- `NameDnsDomain` (12)
- `NameGivenName` (13)
- `NameSurname` (14)

#### GetComputerNameW

No additional fields (captures only the fact that the function was called).

#### GetComputerNameExW

| Field | Description |
|-------|-------------|
| `NameType` | Numeric value of the requested computer name format |
| `NameTypeStr` | String representation of the name type |

Possible `NameTypeStr` values:
- `NetBIOS` (0)
- `DnsHostname` (1)
- `DnsDomain` (2)
- `DnsFullyQualified` (3)
- `PhysicalNetBIOS` (4)
- `PhysicalDnsHostname` (5)
- `PhysicalDnsDomain` (6)
- `PhysicalDnsFullyQualified` (7)

#### IsNativeVhdBoot

No additional fields (captures only the fact that the function was called).

#### DefineDosDeviceW

| Field | Description |
|-------|-------------|
| `Flags` | Combination of flags controlling the operation |
| `DeviceName` | The MS-DOS device name being defined |
| `TargetPath` | The path the device name will be mapped to |

Possible flag values:
- `DDD_RAW_TARGET_PATH` (0x1)
- `DDD_REMOVE_DEFINITION` (0x2)
- `DDD_EXACT_MATCH_ON_REMOVE` (0x3)
- `DDD_NO_BROADCAST_SYSTEM` (0x4)

#### GetAdaptersAddresses

| Field | Description |
|-------|-------------|
| `Family` | Address family filter |
| `Flags` | Flags specifying what information to retrieve |

Possible `Family` values:
- `AF_UNSPEC` (0) - Unspecified
- `AF_INET` (2) - IPv4
- `AF_INET6` (23) - IPv6

Possible `Flags` values (can be combined):
- `GAA_FLAG_SKIP_UNICAST` (0x0001)
- `GAA_FLAG_SKIP_ANYCAST` (0x0002)
- `GAA_FLAG_SKIP_MULTICAST` (0x0004)
- `GAA_FLAG_SKIP_DNS_SERVER` (0x0008)
- `GAA_FLAG_INCLUDE_PREFIX` (0x0010)
- `GAA_FLAG_SKIP_FRIENDLY_NAME` (0x0020)
- `GAA_FLAG_INCLUDE_WINS_INFO` (0x0040)
- `GAA_FLAG_INCLUDE_GATEWAYS` (0x0080)
- `GAA_FLAG_INCLUDE_ALL_INTERFACES` (0x0100)
- `GAA_FLAG_INCLUDE_ALL_COMPARTMENTS` (0x0200)
- `GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER` (0x0400)

#### WNetGetProviderNameW

| Field | Description |
|-------|-------------|
| `NetType` | Network type identifier |

## Example Output

### JSON Format

```json
{"Plugin": "envmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "GetComputerNameExW", "NameType": 3, "NameTypeStr": "DnsFullyQualified"}
```

```json
{"Plugin": "envmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "SspipGetUserName", "ExtendedNameFormat": 2, "ExtendedNameFormatStr": "NameSamCompatible"}
```

```json
{"Plugin": "envmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "GetAdaptersAddresses", "Family": "AF_INET", "Flags": "GAA_FLAG_INCLUDE_PREFIX|GAA_FLAG_INCLUDE_GATEWAYS"}
```

```json
{"Plugin": "envmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "DefineDosDeviceW", "Flags": "DDD_RAW_TARGET_PATH", "DeviceName": "X:", "TargetPath": "\\Device\\HarddiskVolume1"}
```

```json
{"Plugin": "envmon", "TimeStamp": "1234567890.123456", "PID": 1234, "PPID": 5678, "TID": 9012, "UserName": "DOMAIN\\user", "UserId": 1000, "ProcessName": "malware.exe", "Method": "WNetGetProviderNameW", "NetType": 131072}
```
