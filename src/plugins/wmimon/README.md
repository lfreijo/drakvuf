# WMIMon Plugin

## Overview

The WMIMon plugin monitors Windows Management Instrumentation (WMI) activity within a guest virtual machine. It intercepts and logs WMI operations by hooking into the COM object creation process and subsequently tracing WMI-specific method calls.

The plugin works by:
1. Hooking `CoCreateInstance` in ole32.dll (Windows 7) or combase.dll (Windows 8+)
2. Detecting when the WMI Locator object (`CLSID_WbemLocator`) is instantiated
3. Dynamically hooking the `IWbemLocator::ConnectServer` method via vtable interception
4. After a successful connection, hooking `IWbemServices` methods:
   - `ExecQuery` - Captures WQL queries executed against WMI
   - `GetObject` - Captures WMI object retrieval operations
   - `ExecMethod` - Captures WMI method execution calls

This plugin is useful for detecting malware that uses WMI for reconnaissance, lateral movement, or persistence mechanisms.

## Supported Operating Systems

- **Windows only** (Windows 7 and later)
  - Windows 7: Uses ole32.dll for COM hooks
  - Windows 8+: Uses combase.dll for COM hooks

Linux is not supported by this plugin.

## Configuration Options

The plugin requires JSON debug profile files for the Windows DLLs it hooks:

| Option | Command Line | Description | Required |
|--------|--------------|-------------|----------|
| `ole32_profile` | `--json-ole32` | Path to JSON debug profile for ole32.dll | Yes |
| `wow_ole32_profile` | `--json-wow-ole32` | Path to JSON debug profile for SysWOW64/ole32.dll | Yes (64-bit guests) |
| `combase_profile` | `--json-combase` | Path to JSON debug profile for combase.dll | Yes (Windows 8+) |

### Profile Requirements by Windows Version

- **Windows 7**: Requires `ole32_profile`
- **Windows 8 and later**: Requires `combase_profile`
- **64-bit systems**: Additionally requires `wow_ole32_profile` for monitoring 32-bit processes

## How to Enable the Plugin

The WMIMon plugin is **disabled by default** (listed under deprecated plugins in meson_options.txt).

### Build Configuration

Enable the plugin during the meson build configuration:

```bash
meson setup build -Dplugin-wmimon=true
```

Or reconfigure an existing build:

```bash
meson configure build -Dplugin-wmimon=true
```

### Runtime Usage

When running DRAKVUF with the plugin enabled, provide the required JSON profiles:

```bash
drakvuf -r <rekall_profile> -d <domain> \
    --json-ole32 /path/to/ole32.json \
    --json-combase /path/to/combase.json \
    --json-wow-ole32 /path/to/wow64_ole32.json
```

## Output Format

The plugin outputs events using DRAKVUF's standard output format (controlled by the `-o` option). Each event includes standard process context information plus operation-specific fields.

### Common Output Fields

All events include the standard DRAKVUF process context:
- Timestamp
- vCPU number
- Process name
- Process ID (PID)
- Parent Process ID (PPID)
- User ID
- Thread ID

### Operation-Specific Fields

#### ConnectServer Event
Logged when `IWbemLocator::ConnectServer` is called to connect to a WMI namespace.

| Field | Description |
|-------|-------------|
| `Resource` | The WMI namespace being connected to (e.g., `root\cimv2`, `root\subscription`) |

#### ExecQuery Event
Logged when `IWbemServices::ExecQuery` is called to execute a WQL query.

| Field | Description |
|-------|-------------|
| `Command` | The WQL query string being executed |

#### GetObject Event
Logged when `IWbemServices::GetObject` is called to retrieve a WMI object.

| Field | Description |
|-------|-------------|
| `Object` | The WMI object path being retrieved |

#### ExecMethod Event
Logged when `IWbemServices::ExecMethod` is called to execute a method on a WMI object.

| Field | Description |
|-------|-------------|
| `Object` | The WMI object on which the method is being executed |
| `Function` | The name of the method being called |

## Example Output

### Default Format

```
[WMIMON] TIME:1234567890 VCPU:0 CR3:0x1aa000 wmimon ProcessName="powershell.exe" PID=1234 PPID=456 Resource="root\cimv2"
[WMIMON] TIME:1234567891 VCPU:0 CR3:0x1aa000 wmimon ProcessName="powershell.exe" PID=1234 PPID=456 Command="SELECT * FROM Win32_Process"
[WMIMON] TIME:1234567892 VCPU:0 CR3:0x1aa000 wmimon ProcessName="powershell.exe" PID=1234 PPID=456 Object="Win32_Process.Handle=\"1234\""
[WMIMON] TIME:1234567893 VCPU:0 CR3:0x1aa000 wmimon ProcessName="wmic.exe" PID=5678 PPID=1234 Object="Win32_Process" Function="Create"
```

### JSON Format (with `-o json`)

```json
{"Plugin":"wmimon","TimeStamp":"1234567890","VCPU":0,"CR3":"0x1aa000","ProcessName":"powershell.exe","PID":1234,"PPID":456,"Resource":"root\\cimv2"}
{"Plugin":"wmimon","TimeStamp":"1234567891","VCPU":0,"CR3":"0x1aa000","ProcessName":"powershell.exe","PID":1234,"PPID":456,"Command":"SELECT * FROM Win32_Process"}
{"Plugin":"wmimon","TimeStamp":"1234567892","VCPU":0,"CR3":"0x1aa000","ProcessName":"powershell.exe","PID":1234,"PPID":456,"Object":"Win32_Process.Handle=\"1234\""}
{"Plugin":"wmimon","TimeStamp":"1234567893","VCPU":0,"CR3":"0x1aa000","ProcessName":"wmic.exe","PID":5678,"PPID":1234,"Object":"Win32_Process","Function":"Create"}
```

## Technical Details

### Monitored COM Interfaces

The plugin monitors the following COM interfaces and their methods:

- **IWbemLocator** (CLSID: `4590f811-1d3a-11d0-891f-00aa004b2e24`, IID: `dc12a687-737f-11cf-884d-00aa004b2e24`)
  - `ConnectServer` (vtable index 3)

- **IWbemServices** (obtained from `ConnectServer`)
  - `GetObject` (vtable index 6)
  - `ExecQuery` (vtable index 20)
  - `ExecMethod` (vtable index 24)

### Limitations

- The plugin is marked as **deprecated** in the build system
- WOW64 (32-bit process) support code is commented out in the current implementation
- Only monitors processes that create new WMI connections; does not intercept connections already established before monitoring starts
