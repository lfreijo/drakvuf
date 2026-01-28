# Unix Socket Monitor Plugin (unixsocketmon)

## Overview

The `unixsocketmon` plugin monitors socket send operations on Linux systems by hooking the kernel function `sock_sendmsg`. When a message is sent through any socket, this plugin captures and logs the socket family type, message size, and message content.

The plugin supports all standard Linux socket address families (AF_LOCAL, AF_INET, AF_INET6, AF_NETLINK, AF_BLUETOOTH, etc.) and outputs the message content either as a printable UTF-8 string or as a hexadecimal binary representation depending on whether the content is human-readable.

## Supported Operating Systems

- **Linux**: Yes
- **Windows**: No

## Configuration Options

### Command-line Options

| Option | Description |
|--------|-------------|
| `--unixsocketmon-max-size-print <size>` | Maximum number of bytes to capture and display from socket messages. If a message exceeds this size, only the first `<size>` bytes are captured for output. |

### Build Configuration

The plugin is enabled by default. To disable it during build:

```bash
# Using Meson
meson configure -Dplugin-unixsocketmon=false

# Using Autotools (configure)
./configure --disable-plugin-unixsocketmon
```

## How to Enable the Plugin

The plugin is enabled by default when building DRAKVUF with the `plugin-unixsocketmon` meson option set to `true` (the default).

To explicitly enable during build:

```bash
meson setup build -Dplugin-unixsocketmon=true
```

At runtime, enable the plugin by including `unixsocketmon` in the list of active plugins.

## Output Format

### Standard Fields

Every output record includes these standard DRAKVUF fields (provided by the output framework):

| Field | Description |
|-------|-------------|
| TIME | Timestamp of the event (seconds.microseconds) |
| VCPU | Virtual CPU number where the event occurred |
| CR3 | CR3 register value (page directory base) |
| ProcessName | Name of the process that triggered the event |
| UID | User ID of the process |
| PID | Process ID |
| PPID | Parent Process ID |

### Plugin-specific Fields

| Field | Description |
|-------|-------------|
| Type | Socket address family type (e.g., AF_LOCAL, AF_INET, AF_INET6, AF_NETLINK) |
| Size | Total size of the message in bytes |
| Value | Message content - displayed as escaped UTF-8 string if printable, or as hexadecimal if binary |

### Supported Socket Family Types

The plugin recognizes and reports all standard Linux socket address families:

- AF_LOCAL (Unix domain sockets)
- AF_INET (IPv4)
- AF_INET6 (IPv6)
- AF_NETLINK (Kernel/user-space communication)
- AF_PACKET (Low-level packet interface)
- AF_BLUETOOTH
- AF_VSOCK (VM sockets)
- And many more (AX25, IPX, APPLETALK, BRIDGE, X25, etc.)

## Example Output

### Default Format (printable string content)

```
[UNIXSOCKETMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "process_name" sock_sendmsg UID:1000 PID:1234 PPID:1000 Type:AF_INET Size:48 Value:GET / HTTP/1.1\r\nHost: example.com\r\n
```

### Default Format (binary content)

```
[UNIXSOCKETMON] TIME:1234567890.123456 VCPU:0 CR3:0x1A2B3C4D "process_name" sock_sendmsg UID:1000 PID:1234 PPID:1000 Type:AF_NETLINK Size:20 Value:0102030405060708090a0b0c0d0e0f10
```

### JSON Format (printable string content)

```json
{
  "Plugin": "unixsocketmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1A2B3C4D",
  "ProcessName": "process_name",
  "Method": "sock_sendmsg",
  "UID": 1000,
  "PID": 1234,
  "PPID": 1000,
  "Type": "AF_INET",
  "Size": 48,
  "Value": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n"
}
```

### JSON Format (binary content)

```json
{
  "Plugin": "unixsocketmon",
  "TimeStamp": "1234567890.123456",
  "VCPU": 0,
  "CR3": "0x1A2B3C4D",
  "ProcessName": "process_name",
  "Method": "sock_sendmsg",
  "UID": 1000,
  "PID": 1234,
  "PPID": 1000,
  "Type": "AF_NETLINK",
  "Size": 20,
  "Value": "0102030405060708090a0b0c0d0e0f10"
}
```

## Notes

- The plugin determines if message content is printable by checking for unprintable control characters (0x00-0x1F, excluding tab, carriage return, and newline). If unprintable characters are found before any null terminators, the content is displayed as hexadecimal.
- The `Size` field always reports the actual total message size, while `Value` may be truncated based on the `--unixsocketmon-max-size-print` configuration.
- The plugin hooks `sock_sendmsg` which is a kernel function called for all socket send operations, regardless of the userspace API used (send, sendto, sendmsg, write, etc.).
