# HIDSIM Plugin

## Overview

The HIDSIM (Human Interface Device Simulation) plugin provides functionality to inject Human Interface Device (HID) events into a Xen guest virtual machine under investigation. It utilizes the QEMU Machine Protocol (QMP) to send mouse movements, clicks, and keyboard events to the guest system.

The plugin operates in two primary modes:

1. **Random Mouse Movement Mode**: Generates random mouse movements and optionally clicks within the guest. When GUI monitoring is enabled, it can detect and automatically click buttons in dialog boxes.

2. **Template Injection Mode**: Replays pre-recorded HID events from a binary template file created by the `hiddump` helper utility.

### Key Features

- Injects mouse movements and clicks via QMP's `input-send-event` command
- Supports keyboard event injection (keypresses and releases)
- Can replay pre-recorded evdev events from template files
- Optional GUI monitoring to detect and click buttons automatically (Windows 7 only)
- Smooth cursor movement simulation using gaussian-distributed timing
- Automatic button detection based on text matching (e.g., "OK", "Yes", "Continue", "Install")

## Supported Operating Systems

| Feature | Windows 7 | Other Windows Versions | Linux |
|---------|-----------|------------------------|-------|
| HID Injection (mouse/keyboard) | Yes | Yes | Yes |
| GUI Monitoring & Auto-clicking | Yes | No | No |

**Note**: GUI reconstruction and automatic button clicking is only supported on Windows 7. The plugin detects the guest OS version and automatically disables GUI monitoring if the guest is not Windows 7.

## Configuration Options

### Command Line Arguments

| Option | Description |
|--------|-------------|
| `--hid-template <path>` | Path to a binary template file containing pre-recorded HID events. If not specified, the plugin generates random mouse movements. The template file must be created using the `hiddump` helper utility. |
| `--hid-monitor-gui` | Enable GUI monitoring to detect and click buttons automatically. Requires a win32k profile specified via `-W`. Only works on Windows 7 guests. |
| `--hid-random-clicks` | When no template is specified, inject random clicks and double clicks. Spares the bottom-left 20% of the screen to avoid clicking on taskbar/icons. |
| `-W <path>` | Path to the win32k.sys JSON profile (required for `--hid-monitor-gui`). |

### Configuration Structure

The plugin accepts the following configuration parameters:

```cpp
struct hidsim_config
{
    const char* template_fp;     // Path to HID template file
    const char* win32k_profile;  // Path to win32k.sys JSON profile
    bool is_monitor;             // Enable GUI monitoring
    bool is_rand_clicks;         // Enable random clicks
};
```

## How to Enable the Plugin

### Build Configuration

The plugin is enabled by default. To explicitly enable or disable it during the build:

```bash
# Enable (default)
meson setup build -Dplugin-hidsim=true

# Disable
meson setup build -Dplugin-hidsim=false
```

The meson option is defined in `meson_options.txt`:
```
option('plugin-hidsim', type : 'boolean', value : true)
```

### Runtime Usage

Enable the plugin at runtime using the `-a` flag:

```bash
# Basic usage with random mouse movements
sudo ./src/drakvuf -r <ISF-file.json> -d <domID> -a hidsim

# With verbose output
sudo ./src/drakvuf -r <ISF-file.json> -d <domID> -a hidsim -v

# With GUI monitoring (Windows 7 only)
sudo ./src/drakvuf -r <ISF-file.json> -W <Win32K-ISF-file.json> -d <domID> -a hidsim --hid-monitor-gui

# With pre-recorded template
sudo ./src/drakvuf -r <ISF-file.json> -d <domID> -a hidsim --hid-template /path/to/template.bin

# With random clicks enabled
sudo ./src/drakvuf -r <ISF-file.json> -d <domID> -a hidsim --hid-random-clicks
```

## Output Format

The HIDSIM plugin is primarily an input simulation plugin and does not produce structured output events like other DRAKVUF plugins. Instead, it provides debug logging when verbose mode (`-v`) is enabled.

### Debug Output Messages

When running with verbose mode, the plugin outputs debug messages to track its operation:

| Message | Description |
|---------|-------------|
| `[HIDSIM] Using Unix domain socket: <path>` | Shows the QMP socket path being used |
| `[HIDSIM] Using template file: <path>` | Indicates template file being used |
| `[HIDSIM] GUI monitoring requested` | GUI monitoring has been enabled |
| `[HIDSIM] GUI reconstruction supported on Windows 7` | Platform supports GUI monitoring |
| `[HIDSIM] GUI reconstruction is NOT supported on this guest system` | Platform does not support GUI monitoring |
| `[HIDSIM] HID injection started` | Injection thread has started |
| `[HIDSIM] Stopping HID injection` | Plugin is shutting down |
| `[HIDSIM] [INJECTOR] Screen dimension: <W> x <H>` | Detected screen resolution |
| `[HIDSIM] [INJECTOR] Injecting random mouse movements` | Random injection mode active |
| `[HIDSIM] [INJECTOR] Running template injection` | Template injection mode active |
| `[HIDSIM] [INJECTOR] Clicking now at <X> x <Y>` | Mouse click being performed |
| `[HIDSIM] [MONITOR] Started GUI reconstruction thread` | GUI monitoring thread started |
| `[HIDSIM] [MONITOR] Detected GUI update` | Window show event detected |
| `[HIDSIM] [MONITOR] Found "<text>"-button to click at (<X>, <Y>)` | Clickable button detected |

### QMP Command Output (Debug Mode)

When verbose mode is enabled, the plugin also outputs the JSON QMP commands being sent:

```json
{ "execute": "input-send-event", "arguments": { "events": [ { "type": "abs", "data": { "axis": "x", "value": 16384 } }, { "type": "abs", "data": { "axis": "y", "value": 16384 } } ] } }
```

### Error Messages

Error messages are written to stderr:

| Message | Description |
|---------|-------------|
| `[HIDSIM] [INJECTOR] Could not connect to Unix Domain Socket <path>` | Failed to connect to QMP |
| `[HIDSIM] [INJECTOR] Error opening file <path>` | Template file not found |
| `[HIDSIM] [INJECTOR] Not a valid HID template file. Stopping` | Invalid template format |
| `[HIDSIM] [INJECTOR] Error performing HID injection` | General injection error |
| `[HIDSIM] [MONITOR] Plugin failed to load JSON debug info for win32k.sys` | Invalid win32k profile |

## Dependencies

The plugin requires the following libraries:
- **pthreads**: For multi-threaded operation (injection and GUI monitoring threads)
- **json-c**: For JSON parsing and QMP command construction
- **glib**: For various utility functions

## Architecture

The plugin operates using multiple threads:

1. **Main Thread**: Initializes the plugin and manages lifecycle
2. **Injection Thread**: Handles HID event injection via QMP
3. **GUI Reconstruction Thread** (optional): Monitors for GUI updates and identifies clickable buttons

Communication between threads uses atomic variables:
- `has_to_stop`: Signals threads to terminate
- `coords`: Passes click coordinates from the monitor to the injector

## Button Detection (GUI Monitoring)

When GUI monitoring is enabled, the plugin looks for buttons with the following text labels (case-insensitive):

- agree, accept, continue, yes, ok, go, run, click
- enable, try again, next, new, install, extract
- execute, launch, download, load, allow access

The detection uses heuristics including:
- Window class filtering (ignores menus, desktop, dialog boxes, etc.)
- Size ratio checking (buttons must be reasonably sized)
- Visibility checking (only visible windows)
- Text matching within the first few characters

## Related Tools

- **hiddump** (`src/helpers/hiddump/`): Utility to capture HID events and create template files for replay
