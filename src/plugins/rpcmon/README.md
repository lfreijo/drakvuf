# RPCMON Plugin

## Overview

The RPCMON plugin monitors Windows Remote Procedure Call (RPC) activity by hooking usermode RPC runtime functions in `rpcrt4.dll`. It intercepts both client-side RPC calls and server-side RPC message processing, extracting RPC interface identifiers and procedure numbers to provide visibility into inter-process and network RPC communications.

The plugin hooks the following RPC runtime functions:

**Client-side RPC calls:**
- `NdrAsyncClientCall` - Asynchronous RPC client call
- `NdrAsyncClientCall2` - Asynchronous RPC client call (version 2)
- `NdrClientCall` - Synchronous RPC client call
- `NdrClientCall2` - Synchronous RPC client call (version 2)
- `NdrClientCall3` - RPC client call (version 3, uses proxy info)
- `NdrClientCall4` - RPC client call (version 4)

**Server-side RPC message processing:**
- `I_RpcReceive` - Internal RPC receive function
- `I_RpcSend` - Internal RPC send function
- `I_RpcSendReceive` - Internal RPC send/receive function

## Supported Operating Systems

- **Windows**: Fully supported (x86 and x64)
- **Linux**: Not supported (the plugin hooks Windows-specific RPC runtime DLLs)

## Requirements

- Usermode hooking must be supported (`drakvuf_are_userhooks_supported()` must return true)

## Configuration Options

This plugin has no additional configuration options beyond the standard DRAKVUF plugin configuration.

## How to Enable the Plugin

The plugin is enabled by default. To explicitly control it during build configuration:

```bash
# Enable the plugin (default)
meson setup build -Dplugin-rpcmon=true

# Disable the plugin
meson setup build -Dplugin-rpcmon=false
```

## Output Format

The plugin outputs events in the configured DRAKVUF output format (JSON, CSV, KV, or default). Each event contains the following fields:

### Base Fields (provided by DRAKVUF framework)

| Field | Description |
|-------|-------------|
| `Plugin` | Always "rpcmon" |
| `TimeStamp` | Event timestamp in seconds.microseconds format |
| `PID` | Process ID of the calling process |
| `PPID` | Parent process ID |
| `TID` | Thread ID |
| `UserId` | User ID |
| `ProcessName` | Name of the process making the RPC call |
| `Method` | Name of the hooked RPC function |
| `EventUID` | Unique event identifier |

### Plugin-specific Fields

| Field | Description |
|-------|-------------|
| `Event` | Always "api_called" |
| `CalledFrom` | Return address (RIP register value) in hexadecimal |
| `ReturnValue` | Function return value (RAX register value) in hexadecimal |
| `Arguments` | Array of function arguments |
| `Extra` | Array of extracted RPC metadata (see below) |
| `ExtraNum` | Array of numeric RPC metadata (see below) |

### Extra Fields (when available)

Depending on the hooked function, the following extra fields may be present:

| Field | Description | Present For |
|-------|-------------|-------------|
| `InterfaceId` | RPC interface GUID in standard format | All hooks when parseable |
| `TransferSyntax` | Transfer syntax GUID | `NdrClientCall*`, `NdrAsyncClientCall*` |
| `ProcedureNumber` | Procedure number from format string | `NdrClientCall*`, `NdrAsyncClientCall*` |
| `ProcNum` | Procedure number from RPC message | `I_RpcReceive`, `I_RpcSend`, `I_RpcSendReceive` |

## Example Output

### JSON Format

```json
{
  "Plugin": "rpcmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 5678,
  "TID": 9012,
  "UserId": 0,
  "ProcessName": "svchost.exe",
  "Method": "NdrClientCall2",
  "EventUID": "0x1234",
  "Event": "api_called",
  "CalledFrom": "0x7ff812345678",
  "ReturnValue": "0x0",
  "Arguments": ["140701234567890", "140701234568000"],
  "Extra": [
    {"InterfaceId": "12345678-1234-1234-1234-123456789ABC"},
    {"TransferSyntax": "8A885D04-1CEB-11C9-9FE8-08002B104860"}
  ],
  "ExtraNum": [
    {"ProcedureNumber": 5}
  ]
}
```

### Server-side RPC Message Example

```json
{
  "Plugin": "rpcmon",
  "TimeStamp": "1234567890.654321",
  "PID": 5678,
  "PPID": 1234,
  "TID": 3456,
  "UserId": 0,
  "ProcessName": "lsass.exe",
  "Method": "I_RpcReceive",
  "EventUID": "0x5678",
  "Event": "api_called",
  "CalledFrom": "0x7ff823456789",
  "ReturnValue": "0x0",
  "Arguments": ["140702345678901"],
  "Extra": [
    {"InterfaceId": "ABCDEF01-2345-6789-ABCD-EF0123456789"}
  ],
  "ExtraNum": [
    {"ProcNum": 12}
  ]
}
```

## Technical Details

### RPC Structure Parsing

The plugin parses several Windows RPC runtime structures to extract interface information:

- `MIDL_STUB_DESC` - Contains pointer to RPC interface information
- `MIDL_STUBLESS_PROXY_INFO` - Contains pointer to stub descriptor (for `NdrClientCall3`)
- `RPC_CLIENT_INTERFACE` - Contains interface ID and transfer syntax GUIDs
- `RPC_MESSAGE` - Contains procedure number and interface information for server-side calls

### Architecture Support

The plugin correctly handles both 32-bit and 64-bit processes, using appropriate structure offsets and pointer sizes for each architecture.

### GUID Format

Interface and transfer syntax GUIDs are output in the standard Windows GUID format:
```
"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
```
