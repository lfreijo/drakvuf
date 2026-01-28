# tlsmon Plugin

## Overview

The tlsmon plugin extracts TLS (Transport Layer Security) session secrets from Windows guest virtual machines. It monitors the `SslGenerateSessionKeys` function in `ncrypt.dll` within the `lsass.exe` process to capture TLS master keys and client random values during TLS handshakes.

The extracted secrets are output in a format compatible with Wireshark's TLS decryption feature, allowing analysts to decrypt captured TLS traffic for forensic analysis or malware research.

### How It Works

On Windows, processes that establish TLS connections using the Schannel API do so through the Local Security Authority Subsystem Service (lsass.exe). The lsass process performs the TLS handshake on behalf of the initiating process, and the TLS secrets never leave lsass's memory space. This plugin hooks into lsass to extract these secrets at the moment they are generated.

The plugin:
1. Locates the running `lsass.exe` process
2. Sets a usermode hook on the `SslGenerateSessionKeys` function in `ncrypt.dll`
3. When the hook triggers, extracts the master key from NCryptSslKey structures
4. Extracts client random values from NCryptBuffer structures
5. Outputs the secrets in a format usable by Wireshark

## Supported Operating Systems

- **Windows**: Supported (hooks Schannel TLS implementation via lsass.exe)
- **Linux**: Not supported

## Configuration Options

The tlsmon plugin has no additional configuration options. It automatically hooks the lsass process when enabled.

### Requirements

- Usermode hooking must be supported and enabled in DRAKVUF
- A Windows guest VM with the lsass.exe process running

## How to Enable the Plugin

The plugin is enabled by default. To configure it during the meson build:

```bash
# Enable tlsmon (default)
meson setup build -Dplugin-tlsmon=true

# Disable tlsmon
meson setup build -Dplugin-tlsmon=false
```

To check current configuration:
```bash
meson configure build | grep tlsmon
```

## Output Format

The plugin outputs events using DRAKVUF's standard output format system, which supports multiple formats (default, JSON, CSV, key-value).

### Output Fields

Each event includes standard DRAKVUF fields plus the following tlsmon-specific fields:

| Field | Description |
|-------|-------------|
| `client_random` | 32-byte client random value in hexadecimal format (64 hex characters). This value is sent by the client during the TLS handshake and uniquely identifies the session. |
| `master_key` | 48-byte TLS master secret in hexadecimal format (96 hex characters). This is the derived session key used for encrypting TLS traffic. |

### Standard Fields

In addition to the plugin-specific fields, each event includes standard DRAKVUF event information such as:
- Timestamp
- Plugin name (`tlsmon`)
- Process information (PID, PPID, process name)
- Thread ID
- User context information

## Example Output

### JSON Format

```json
{
  "Plugin": "tlsmon",
  "TimeStamp": "1234567890.123456",
  "PID": 636,
  "PPID": 456,
  "ProcessName": "lsass.exe",
  "client_random": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "master_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

### Using with Wireshark

The output can be converted to Wireshark's SSLKEYLOGFILE format:

```
CLIENT_RANDOM <client_random> <master_key>
```

For example:
```
CLIENT_RANDOM a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

To use in Wireshark:
1. Go to Edit > Preferences > Protocols > TLS
2. Set "(Pre)-Master-Secret log filename" to your keylog file
3. Open the corresponding packet capture

## Technical Details

### Hooked Function

- **DLL**: `ncrypt.dll`
- **Function**: `SslGenerateSessionKeys`

### Internal Structures

The plugin parses the following Windows internal structures:

- `NCryptSslKey` - Contains a pointer to the master secret structure (validated by magic bytes `0x44444442`)
- `SslMasterSecret` - Contains the 48-byte master key (validated by magic bytes `0x73736c35`)
- `NCryptBuffer` / `NCryptBufferDesc` - Contains client and server random values

### Constants

- Client random size: 32 bytes (0x20)
- Master key size: 48 bytes (0x30)
- Client random buffer type: 20 (`NCRYPTBUFFER_SSL_CLIENT_RANDOM`)
- Server random buffer type: 21 (`NCRYPTBUFFER_SSL_SERVER_RANDOM`)
