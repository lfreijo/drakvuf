# tlsmon - TLS Secret Extraction Plugin

The `tlsmon` plugin extracts TLS session secrets from guest VMs, enabling Wireshark-compatible decryption of encrypted network traffic. It supports Windows (Schannel), Android (BoringSSL), and standard Linux distributions (OpenSSL 3.x).

## Overview

TLS encryption protects network traffic, but for malware analysis and security research, decrypting this traffic is essential. The `tlsmon` plugin captures TLS master secrets and traffic secrets at the moment they're generated, outputting them in a format compatible with Wireshark's SSLKEYLOGFILE.

### Supported Platforms

| Platform | TLS Library | Coverage | Status |
|----------|-------------|----------|--------|
| Windows 10/11 | Schannel | ~90% of apps | Supported |
| Android (BlissOS) | BoringSSL | ~95% of apps | Supported |
| Linux (RHEL/AlmaLinux/etc.) | OpenSSL 3.x | ~70% of apps | Supported |
| Linux | NSS (Firefox) | Firefox only | Not implemented |
| Linux | GnuTLS | GNOME apps | Not implemented |
| Any | Go crypto/tls | Go apps | Cannot hook (embedded) |
| Any | Rust rustls | Rust apps | Cannot hook (embedded) |

## How It Works

### Windows (Schannel)

Windows centralizes TLS handling in `lsass.exe` via the Schannel security provider. The plugin:

1. Hooks `ncrypt.dll!SslGenerateSessionKeys` in the `lsass.exe` process
2. When a TLS handshake completes, extracts the master secret from `NCryptSslKey` structures
3. Reads the client random from the `NCryptBuffer` parameter list
4. Outputs in SSLKEYLOGFILE format: `CLIENT_RANDOM <hex> <master_secret_hex>`

**Advantages:**
- Single hook point catches ALL Windows TLS traffic
- Works for browsers, .NET apps, PowerShell, system services

**Profile Requirements:**
- Only the kernel profile (`-r`) is required
- No additional DLL profiles needed for tlsmon specifically

### Android / BlissOS (BoringSSL)

Android uses BoringSSL (Google's OpenSSL fork) as the system TLS library. The plugin:

1. Scans guest physical memory for `libssl.so` code pages
2. Places INT3 breakpoints on BoringSSL's internal `ssl_log_secret()` function
3. When triggered, reads parameters from registers (x86_64 SysV ABI):
   - `rdi` = SSL* pointer
   - `rsi` = label string ("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", etc.)
   - `rdx` = secret data pointer
   - `rcx` = secret length
4. Reads `client_random` from `ssl->s3->client_random` (32 bytes)
5. Outputs secrets for both TLS 1.2 and TLS 1.3

**Advantages:**
- Single hook catches all processes (shared physical pages)
- Covers ~95% of Android TLS traffic
- Works even without knowing which processes will use TLS

**Profile Requirements:**
- Kernel profile (`-r`)
- BoringSSL libssl profile (`--json-libssl`) containing:
  - `ssl_log_secret` symbol RVA
  - `ssl_st.s3` struct offset
  - `SSL3_STATE.client_random` struct offset

### Linux (OpenSSL 3.x)

Standard Linux distributions (RHEL, AlmaLinux, Ubuntu, Fedora, etc.) use OpenSSL. The plugin:

1. Scans guest physical memory for `libssl.so.3` code pages using reference bytes from host
2. Places INT3 breakpoints on OpenSSL's internal `nss_keylog_int()` function
3. When triggered, reads parameters from registers (x86_64 SysV ABI):
   - `rdi` = label string
   - `rsi` = SSL* pointer (unused)
   - `rdx` = client_random pointer
   - `rcx` = client_random length (32)
   - `r8` = secret pointer
   - `r9` = secret length
4. Outputs TLS 1.3 secrets (all traffic secret types)

**Key Difference from BoringSSL:**
OpenSSL's `nss_keylog_int` passes client_random as a direct parameter, while BoringSSL requires struct traversal.

**Profile Requirements:**
- Kernel profile (`-r`)
- OpenSSL profile (`--json-openssl`) containing `nss_keylog_int` symbol RVA
- Host copy of guest's `libssl.so.3` (`--openssl-libssl`) for reference bytes

## Usage

### Windows

```bash
sudo drakvuf \
  -r /path/to/kernel-profile.json \
  -d windows10 -t 60 -o json \
  -a tlsmon
```

### Android / BlissOS

```bash
sudo drakvuf \
  -r /path/to/kernel-profile.json \
  --json-libssl /path/to/libssl-profile.json \
  -d blissos18 -t 60 -o json \
  -a tlsmon
```

### Linux (OpenSSL)

```bash
sudo drakvuf \
  -r /path/to/kernel-profile.json \
  --json-openssl /path/to/openssl-profile.json \
  --openssl-libssl /path/to/host/libssl.so.3.x.x \
  -d alma9 -t 60 -o json \
  -a tlsmon
```

## Output Format

The plugin outputs JSON events that can be converted to Wireshark's SSLKEYLOGFILE format:

### JSON Output
```json
{
  "Plugin": "tlsmon",
  "TimeStamp": "1234567890.123456",
  "PID": 1234,
  "ProcessName": "/usr/bin/curl",
  "library": "openssl",
  "label": "CLIENT_TRAFFIC_SECRET_0",
  "client_random": "abcd1234...",
  "secret": "efgh5678..."
}
```

### SSLKEYLOGFILE Format
```
CLIENT_TRAFFIC_SECRET_0 abcd1234... efgh5678...
```

### TLS 1.2 vs TLS 1.3

| TLS Version | Labels |
|-------------|--------|
| TLS 1.2 | `CLIENT_RANDOM` (master secret) |
| TLS 1.3 | `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET` |

## Creating Profiles

### BoringSSL Profile (Android)

Use the provided script with a debug (unstripped) libssl.so:

```bash
python3 profiles/gen_libssl_profile.py \
  /path/to/debug/libssl.so \
  -o profiles/blissos18_libssl.json
```

The debug libssl.so must have:
- DWARF debug info (for struct offsets)
- Unstripped .symtab (for `ssl_log_secret` symbol)

For Android, use the symbols directory from the build:
```
out/target/product/x86_64/symbols/system/lib64/libssl.so
```

### OpenSSL Profile (Linux)

For OpenSSL 3.x on stripped production systems (no debug symbols), manual analysis is required:

1. **Extract libssl.so from guest:**
   ```bash
   # Mount guest disk
   sudo qemu-nbd --connect=/dev/nbd0 guest.qcow2
   sudo mount /dev/nbd0pX /mnt
   cp /mnt/usr/lib64/libssl.so.3.x.x ./
   sudo umount /mnt
   sudo qemu-nbd --disconnect /dev/nbd0
   ```

2. **Find the hook function RVA via disassembly:**
   ```bash
   # Find CLIENT_RANDOM string
   strings -t x libssl.so.3.x.x | grep CLIENT_RANDOM

   # Find code referencing it
   objdump -d libssl.so.3.x.x | grep -B 50 "<offset>"

   # Trace back to find nss_keylog_int or similar function
   ```

3. **Create the profile:**
   ```json
   {
     "symbols": {
       "nss_keylog_int": {
         "address": 277584
       }
     },
     "metadata": {
       "format": "6.1.0",
       "source": "libssl.so.3.2.2 (AlmaLinux 9)"
     }
   }
   ```

4. **Keep a copy of libssl.so on the host** for the `--openssl-libssl` parameter.

### Version-Specific Profiles

OpenSSL internal function layouts change between versions. You need a profile matching the guest's exact OpenSSL version:

| Distro | OpenSSL Version | Notes |
|--------|-----------------|-------|
| AlmaLinux 9 | 3.2.2 | RVA 0x43c50 |
| RHEL 9 | 3.0.x - 3.2.x | Different RVA per minor version |
| Ubuntu 22.04 | 3.0.2 | Different RVA |
| Fedora 39+ | 3.1.x+ | Different RVA |

## Limitations

### Cannot Hook Embedded TLS

Applications that embed their own TLS implementation cannot be hooked:

- **Go applications** - Go's `crypto/tls` is compiled into the binary
- **Rust applications** - Often use `rustls` which is statically linked
- **Custom TLS** - Some applications implement their own TLS

For these, consider:
- Network-level analysis (packet capture + traffic analysis)
- Memory forensics (scan for decrypted content)
- Application-specific hooks (if source is known)

### Demand Paging

TLS library code pages may not be in physical memory until a TLS connection is made. The plugin handles this via:

1. **Initial scan** - Scans all physical memory at startup
2. **Deferred scan** - Re-scans after ~32 seconds of syscall activity
3. **Process enumeration** - Finds processes with libssl loaded and hooks via VA

### Multiple Library Copies

On Android, multiple copies of libssl.so may exist (system, vendor, APEX). The plugin scans physical memory to find ALL copies and hooks each unique physical page.

## Architecture

### Files

| File | Purpose |
|------|---------|
| `tlsmon.h/cpp` | OS dispatcher - creates win_tlsmon or linux_tlsmon |
| `win.h/cpp` | Windows Schannel hooks |
| `private.h` | Windows internal structures |
| `linux.h/cpp` | Linux BoringSSL/OpenSSL hooks |
| `linux_private.h` | Linux struct offsets and constants |

### Hook Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                     Physical Memory                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  libssl.so code page (shared by all processes)      │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │  ssl_log_secret() / nss_keylog_int()        │    │    │
│  │  │  [INT3 breakpoint at function entry]        │◄───┼────┼── DRAKVUF trap
│  │  └─────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Process A (curl)     Process B (wget)    Process C (python)│
│       │                    │                    │            │
│       └────────────────────┴────────────────────┘            │
│                   All hit same breakpoint                    │
└─────────────────────────────────────────────────────────────┘
```

By hooking at the physical page level, a single breakpoint catches ALL processes using that library, regardless of virtual address mappings.

## Troubleshooting

### No TLS events captured

1. **Check if hooks were placed:**
   ```bash
   drakvuf ... -v 2>&1 | grep -i "hook placed"
   ```

2. **Verify library version matches profile:**
   - Extract libssl from guest and compare hash
   - Check RVA matches the function in that version

3. **Check if TLS traffic occurred:**
   - Verify network connectivity in guest
   - Try triggering TLS manually (curl https://...)

### Hooks placed but no output

1. **Check callback is correct:**
   - BoringSSL should use `ssl_log_secret_cb`
   - OpenSSL should use `openssl_ssl_log_secret_cb`

2. **Verify register layout:**
   - Run with `-v` to see debug output
   - Check if label/secret reads are failing

### Physical scan finds 0 pages

1. **Verify reference bytes:**
   - Check `--openssl-libssl` points to correct host file
   - Verify file matches guest's libssl version

2. **Library not loaded yet:**
   - Wait for TLS activity before scanning
   - The deferred scan (after ~32s) may find new pages

## References

- [Wireshark SSLKEYLOGFILE](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
- [OpenSSL Keylog Callback](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_keylog_callback.html)
- [BoringSSL Source](https://boringssl.googlesource.com/boringssl/)
