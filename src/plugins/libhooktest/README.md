# libhooktest Plugin

## Overview

The libhooktest plugin is a development and testing utility that demonstrates the usage of the libhook RAII-based hooking API in DRAKVUF. It serves as a reference implementation showing how to properly use the modern hooking mechanisms provided by the `pluginex` base class.

The plugin demonstrates three key hooking patterns:
1. **CR3 Hook**: Monitors CR3 register changes (page table base address changes, typically indicating context switches)
2. **Syscall Hook**: Intercepts calls to `NtProtectVirtualMemory`
3. **Return Hook**: Captures the return from `NtProtectVirtualMemory` calls

This plugin is primarily intended for developers working on DRAKVUF plugins who want to understand how to use the libhook API for creating memory-safe, RAII-managed hooks.

## Supported Operating Systems

- **Windows only**: The plugin hooks `NtProtectVirtualMemory`, which is a Windows NT kernel syscall. This syscall does not exist on Linux systems.

## Configuration Options

This plugin has no runtime configuration options. It is a simple test plugin that automatically sets up its hooks upon initialization.

## How to Enable the Plugin

The libhooktest plugin is **disabled by default** in the build system.

### Meson Build System

To enable the plugin, configure your build with the `-Dplugin-libhooktest=true` option:

```bash
meson setup builddir -Dplugin-libhooktest=true
# or reconfigure an existing build:
meson configure builddir -Dplugin-libhooktest=true
```

Then build:

```bash
ninja -C builddir
```

### Verification

During the meson configuration, the plugin status will be shown in the "Plugins" section of the build summary.

## Output Format

This plugin does not produce structured output to stdout. All output is via `PRINT_DEBUG` macros, which means output is only visible when DRAKVUF is compiled with debug output enabled.

### Debug Messages

When debug output is enabled, the following messages may appear:

| Message | Description |
|---------|-------------|
| `[LIBHOOKTEST] works` | Plugin initialized successfully |
| `[LIBHOOKTEST] CR3 changed` | CR3 register change detected (context switch) |
| `[LIBHOOKTEST] CR3 unhooked` | CR3 hook has been removed (one-shot behavior) |
| `[LIBHOOKTEST] NtProtectVirtualMemory called` | The syscall was intercepted |
| `[LIBHOOKTEST] NtProtectVirtualMemory Return Hook called` | The syscall returned |

## Example Output

When running with debug output enabled, you would see messages like:

```
[LIBHOOKTEST] works
[LIBHOOKTEST] CR3 changed
[LIBHOOKTEST] CR3 unhooked
[LIBHOOKTEST] NtProtectVirtualMemory called
[LIBHOOKTEST] NtProtectVirtualMemory Return Hook called
[LIBHOOKTEST] NtProtectVirtualMemory called
[LIBHOOKTEST] NtProtectVirtualMemory Return Hook called
```

Note: The CR3 hook is a one-shot hook that unhooks itself after the first CR3 change is detected. The syscall and return hooks persist for the lifetime of the plugin.

## Implementation Notes

The plugin uses the following libhook API methods from the `pluginex` base class:

- `createCr3Hook()` - Creates a hook that triggers on CR3 register writes
- `createSyscallHook()` - Creates a hook on a named Windows syscall
- `createReturnHook()` - Creates a hook at the return address of a function call

All hooks are managed via `std::unique_ptr`, providing automatic cleanup when the hook is reset or the plugin is destroyed.
