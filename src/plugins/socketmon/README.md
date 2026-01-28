# Socketmon Plugin

## Overview

The socketmon plugin monitors network socket activity in Windows virtual machines. It intercepts TCP connections, UDP communications, and DNS queries by hooking into kernel-level and user-mode functions. The plugin provides visibility into network communications by capturing:

- **TCP Connections**: Monitors outbound TCP connections by hooking `TcpCreateAndConnectTcbComplete` or `TcpCreateAndConnectTcbRateLimitComplete` in tcpip.sys
- **UDP Traffic**: Captures UDP send operations by hooking `UdpSendMessages` in tcpip.sys
- **DNS Queries**: Intercepts DNS resolution requests by hooking various functions in dnsapi.dll

## Supported Operating Systems

**Windows only** - This plugin does not support Linux guests.

### Supported Windows Versions

| Version | Architecture | Support |
|---------|-------------|---------|
| Windows 7 SP1 | x86 | Supported |
| Windows 7 SP1 | x64 | Supported |
| Windows 8.1 | x64 | Supported |
| Windows Server 2016 | x64 | Supported |
| Windows 10 1803 | x64 | Supported |
| Windows 10 1909 | x64 | Supported |
| Windows Server 2019 | x64 | Supported |
| Windows 10 21H2 | x64 | Supported |
| Windows 10 22H2 | x64 | Supported |
| Windows 10 23H2 | x64 | Supported |
| Windows 10 (32-bit) | x86 | Not Supported |

## Configuration Options

The plugin requires the following configuration:

| Option | Command-Line Flag | Description | Required |
|--------|------------------|-------------|----------|
| tcpip_profile | `-T, --json-tcpip <path>` | Path to JSON debug profile for tcpip.sys | Yes |

The tcpip.sys JSON profile contains symbol information necessary for the plugin to locate and hook the correct kernel functions.

## How to Enable the Plugin

### Meson Build Option

The plugin is enabled by default. To explicitly control it:

```bash
# Enable (default)
meson setup build -Dplugin-socketmon=true

# Disable
meson setup build -Dplugin-socketmon=false
```

### Runtime Requirements

When running DRAKVUF, provide the tcpip.sys JSON profile:

```bash
drakvuf -r <rekall_profile> -d <domain> -T /path/to/tcpip.json [other options]
```

**Note**: The plugin also requires usermode hooking support to be available for DNS query monitoring.

## Output Format

The plugin outputs events in the configured format (default, CSV, KV, or JSON) with the following event types:

### TCP Connection Events

| Field | Type | Description |
|-------|------|-------------|
| Owner | String | Name of the process that owns the connection |
| OwnerId | Number | User ID of the process owner |
| OwnerPID | Number | Process ID of the connection owner |
| OwnerPPID | Number | Parent process ID of the connection owner |
| Protocol | String | Protocol type: `TCPv4` or `TCPv6` |
| LocalIp | String | Local IP address (defaults to `127.0.0.1` for IPv4 or `::1` for IPv6) |
| LocalPort | Number | Local port number |
| RemoteIp | String | Remote IP address being connected to |
| RemotePort | Number | Remote port number |

### UDP Send Events

| Field | Type | Description |
|-------|------|-------------|
| Owner | String | Name of the process sending the UDP packet |
| OwnerId | Number | User ID of the process owner |
| OwnerPID | Number | Process ID of the sender |
| OwnerPPID | Number | Parent process ID of the sender |
| Protocol | String | Protocol type: `UDPv4` or `UDPv6` |
| LocalIp | String | Local IP address |
| LocalPort | Number | Local port number |
| RemoteIp | String | Destination IP address |
| RemotePort | Number | Destination port number |

### DNS Query Events

| Field | Type | Description |
|-------|------|-------------|
| DnsName | String | The domain name being queried |

## Example Output

### TCP Connection (JSON format)

```json
{
  "Plugin": "socketmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1234000",
  "Owner": "chrome.exe",
  "OwnerId": 1000,
  "OwnerPID": 1234,
  "OwnerPPID": 5678,
  "Protocol": "TCPv4",
  "LocalIp": "127.0.0.1",
  "LocalPort": 54321,
  "RemoteIp": "142.250.80.46",
  "RemotePort": 443
}
```

### UDP Send (JSON format)

```json
{
  "Plugin": "socketmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1234000",
  "Owner": "svchost.exe",
  "OwnerId": 0,
  "OwnerPID": 1024,
  "OwnerPPID": 512,
  "Protocol": "UDPv4",
  "LocalIp": "127.0.0.1",
  "LocalPort": 51234,
  "RemoteIp": "8.8.8.8",
  "RemotePort": 53
}
```

### DNS Query (JSON format)

```json
{
  "Plugin": "socketmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1234000",
  "DnsName": "www.example.com"
}
```

## Hooked Functions

### Kernel Mode (tcpip.sys)

- `TcpCreateAndConnectTcbComplete` - TCP connection creation (older Windows versions)
- `TcpCreateAndConnectTcbRateLimitComplete` - TCP connection creation (Windows 7 SP1, Windows 10 1803+)
- `UdpSendMessages` - UDP packet transmission

### User Mode (dnsapi.dll)

- `DnsQuery_W` - Unicode DNS query (all versions)
- `DnsQuery_A` - ASCII DNS query (all versions)
- `DnsQuery_UTF8` - UTF-8 DNS query (all versions)
- `DnsQueryExW` - Extended Unicode DNS query (Windows 7 only)
- `DnsQueryA` - DNS query variant (Windows 7 only)
- `DnsQueryEx` - Extended DNS query (Windows 8+)

## Technical Notes

- IPv4-mapped IPv6 addresses (format `::ffff:x.x.x.x`) are automatically converted to IPv4 representation for consistency with network capture tools
- The plugin uses different internal structures and offsets depending on the Windows version detected at runtime
- DNS monitoring requires usermode hooking support; if unavailable, only kernel-level TCP/UDP monitoring will function
