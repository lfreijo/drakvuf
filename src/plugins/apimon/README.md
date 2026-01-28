# APIMON Plugin

## Overview

The APIMON (API Monitor) plugin provides usermode API call monitoring capabilities for DRAKVUF. It hooks Windows DLL functions at runtime and logs API calls made by monitored processes, including function arguments and return values.

The plugin works by:
1. Loading a configuration file that specifies which DLL functions to monitor
2. Registering usermode hooks when DLLs are loaded into process address space
3. Capturing function arguments when hooked functions are called
4. Optionally capturing return values via return hooks
5. Resolving the calling module for each API call
6. Outputting detailed information about each intercepted call

Additionally, the plugin includes specialized handling for certain Windows Crypto API functions (e.g., `CryptGenKey`) to extract extra information such as generated cryptographic keys.

## Supported Operating Systems

**Windows only** - The plugin relies on Windows-specific usermode hooking infrastructure and is designed to monitor Windows DLL function calls. The example hook configuration file targets Windows 7 x64 DLLs.

## Configuration Options

The plugin is configured via the `apimon_config` structure with the following options:

| Option | Type | Description |
|--------|------|-------------|
| `dll_hooks_list` | `const char*` | Path to a file containing the list of DLL functions to hook. Each line specifies: DLL name, function name, action flags, and argument type definitions. |
| `print_no_addr` | `bool` | When enabled, suppresses printing memory addresses of string arguments in the output (useful for reproducible output). |

### DLL Hooks List File Format

The hook configuration file uses a CSV-like format with the following columns:
```
<dll_name>,<function_name>,<action_flags>,<arg1_type>,<arg2_type>,...
```

**Fields:**
- `dll_name`: Name of the DLL containing the function (e.g., `kernel32.dll`, `ntdll.dll`)
- `function_name`: Name of the function to hook (e.g., `CreateProcessInternalW`)
- `action_flags`: Actions to perform, can include:
  - `log`: Log the API call
  - `log+stack`: Log the API call with stack trace
- `arg_types`: Type definitions for each function argument (e.g., `lpwstr`, `dword`, `handle`, `pvoid`)

**Example entries:**
```
ntdll.dll,LdrLoadDll,log,pwchar,pulong,punicode_string,phandle
kernel32.dll,CreateProcessInternalW,log,lpvoid,lpwstr,lpwstr,lpsecurity_attributes,lpsecurity_attributes,bool,dword,lpvoid,lpwstr,lpstartupinfo,lpprocess_information,lpvoid
advapi32.dll,CryptGenKey,log,hcryptprov,alg_id,dword,hcryptkey
ws2_32.dll,connect,log,socket,struct,int
```

See `example/dll-hooks-list-win7x64` for a comprehensive example targeting Windows 7 x64.

## How to Enable the Plugin

### Build-time Configuration

The plugin is enabled by default in the Meson build system. To explicitly enable or disable it:

```bash
# Enable (default)
meson setup build -Dplugin-apimon=true

# Disable
meson setup build -Dplugin-apimon=false
```

### Runtime Configuration

To use the plugin at runtime, provide the DLL hooks configuration file:

```bash
drakvuf --dll-hooks-list /path/to/dll-hooks-list-file [other options]
```

Optional flag to suppress address printing:
```bash
drakvuf --dll-hooks-list /path/to/dll-hooks-list-file --userhook-no-addr [other options]
```

**Note:** The plugin requires usermode hooking support to be available. If usermode hooking is not supported in your environment, the plugin will not initialize.

## Output Format

The plugin outputs events in the configured DRAKVUF output format (default, CSV, KV, or JSON).

### Event Types

#### 1. `dll_discovered` Event

Emitted when a monitored DLL is discovered/loaded.

| Field | Description |
|-------|-------------|
| `Plugin` | Always `apimon` |
| `Event` | `dll_discovered` |
| `DllName` | Name of the discovered DLL |
| `DllBase` | Base address of the DLL in memory (hex) |
| `PID` | Process ID that loaded the DLL |

#### 2. `dll_loaded` Event (JSON only)

Emitted after hooks are successfully installed on a DLL.

| Field | Description |
|-------|-------------|
| `Plugin` | Always `apimon` |
| `Event` | `dll_loaded` |
| `DllName` | Full path to the DLL |
| `DllBase` | Base address of the DLL (hex) |
| `PID` | Process ID |
| `Rva` | Object containing function names and their RVA offsets |

#### 3. `api_called` Event

Emitted when a hooked API function is called.

| Field | Description |
|-------|-------------|
| `Plugin` | Always `apimon` |
| `Event` | `api_called` |
| `CLSID` | COM Class ID if applicable (optional) |
| `CalledFrom` | Address from which the API was called (hex) |
| `ReturnValue` | Return value of the function (hex) |
| `FromModule` | Name of the module that made the call (optional) |
| `Arguments` | Array of formatted argument values |
| `Extra` | Additional extracted data (e.g., cryptographic keys) |

### Extra Data Fields

For certain hooked functions, additional data is extracted:

| Function | Extra Field | Description |
|----------|-------------|-------------|
| `CryptGenKey` | `generated_key` | Hex-encoded cryptographic key bytes (32-bit processes only) |

## Example Output

### JSON Format

#### DLL Discovered Event
```json
{
  "Plugin": "apimon",
  "Event": "dll_discovered",
  "DllName": "kernel32.dll",
  "DllBase": "0x7ff8a1230000",
  "PID": 1234
}
```

#### DLL Loaded Event
```json
{
  "Plugin": "apimon",
  "Event": "dll_loaded",
  "DllName": "\\Windows\\System32\\kernel32.dll",
  "DllBase": "0x7ff8a1230000",
  "PID": 1234,
  "Rva": {
    "CreateProcessInternalW": 12345,
    "VirtualProtectEx": 67890
  }
}
```

#### API Called Event
```json
{
  "Plugin": "apimon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "PPID": 1000,
  "TID": 5678,
  "UserName": "user",
  "UserId": 1000,
  "ProcessName": "malware.exe",
  "Method": "CreateProcessInternalW",
  "Event": "api_called",
  "CalledFrom": "0x7ff8a1234567",
  "ReturnValue": "0x1",
  "FromModule": "malware.exe",
  "Arguments": [
    "NULL",
    "\"C:\\Windows\\System32\\cmd.exe\"",
    "NULL",
    "NULL",
    "NULL",
    "0",
    "0x0",
    "NULL",
    "NULL",
    "...",
    "...",
    "NULL"
  ]
}
```

#### CryptGenKey with Extra Data
```json
{
  "Plugin": "apimon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "ProcessName": "crypto_app.exe",
  "Method": "CryptGenKey",
  "Event": "api_called",
  "CalledFrom": "0x401234",
  "ReturnValue": "0x1",
  "FromModule": "crypto_app.exe",
  "Arguments": [
    "0x12345678",
    "0x6610",
    "0x800000",
    "0x12340000"
  ],
  "Extra": {
    "generated_key": "a1b2c3d4e5f6..."
  }
}
```

## Files

- `apimon.cpp` - Main plugin implementation
- `apimon.h` - Plugin header with class and config definitions
- `crypto.cpp` - Specialized handlers for Windows Crypto API functions
- `crypto.h` - Crypto API structures and function declarations
- `example/dll-hooks-list-win7x64` - Example hook configuration for Windows 7 x64
