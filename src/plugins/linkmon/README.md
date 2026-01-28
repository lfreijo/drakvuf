# Linkmon Plugin

## Overview

The linkmon plugin monitors file system link creation operations on Windows. It detects when processes create hard links, symbolic links (symlinks), or junction points. This is useful for:

- Detecting privilege escalation attempts that abuse file system links
- Monitoring file system manipulation for forensic analysis
- Identifying malware that uses symbolic links for persistence or evasion
- Tracking junction point creation for directory redirection attacks

The plugin hooks Windows NT kernel functions to intercept link creation at the system call level.

## Supported Operating Systems

**Windows only**

This plugin hooks Windows NT kernel system calls (`NtSetInformationFile` and `NtFsControlFile`) and relies on Windows-specific data structures. It is not supported on Linux or other operating systems.

## Configuration Options

The plugin requires the following configuration:

| Option | Description | Required |
|--------|-------------|----------|
| `ole32_profile` | Path to the JSON debug profile for ole32.dll | Yes |

The ole32.dll JSON profile contains structure offset information needed to parse the `FILE_LINK_INFORMATION` and `REPARSE_DATA_BUFFER` structures used by the Windows kernel.

## How to Enable the Plugin

### Meson Build Option

The plugin is enabled by default. To explicitly control it during the build:

```bash
# Enable (default)
meson configure -Dplugin-linkmon=true

# Disable
meson configure -Dplugin-linkmon=false
```

### Runtime Requirements

At runtime, you must provide the ole32.dll JSON profile using the appropriate command-line option when starting DRAKVUF.

## Monitored Functions

The plugin sets breakpoints on the following NT kernel functions:

| Function | Description |
|----------|-------------|
| `NtSetInformationFile` | Hooked to detect hard link creation via `FileLinkInformation` (class 0xB) |
| `NtFsControlFile` | Hooked to detect symbolic link and junction point creation via `FSCTL_SET_REPARSE_POINT` (0x900A4) |

## Link Types Detected

| Link Type | Description | Detection Method |
|-----------|-------------|------------------|
| `hardlink` | Hard link to an existing file | `NtSetInformationFile` with `FileLinkInformation` |
| `symlink` | Symbolic link (file or directory) | `NtFsControlFile` with reparse tag `IO_REPARSE_TAG_SYMLINK` (0xA000000C) |
| `junction` | Directory junction point | `NtFsControlFile` with reparse tag `IO_REPARSE_TAG_MOUNT_POINT` (0xA0000003) |

## Output Format

The plugin outputs events using DRAKVUF's standard output format system, supporting DEFAULT, JSON, KV, and CSV formats.

### Output Fields

Each event contains the following fields:

| Field | Description |
|-------|-------------|
| `Plugin` | Always "linkmon" |
| `TimeStamp` / `TIME` | Timestamp of the event (seconds.microseconds) |
| `PID` | Process ID of the process creating the link |
| `PPID` | Parent process ID |
| `TID` | Thread ID (JSON format) |
| `UserId` | User ID / Session ID of the process |
| `ProcessName` | Name of the process creating the link |
| `FileName` | The path of the link being created |
| `LinkType` | Type of link: "hardlink", "symlink", or "junction" |
| `LinkTarget` | The target path that the link points to |
| `Flags` | Symlink flags (only present for symbolic links, hexadecimal) |

### Field Details

- **FileName**: For hard links, this is the new link path. For symlinks and junctions, this is the path where the reparse point is being set.
- **LinkTarget**: The existing file or directory that the link will reference.
- **Flags**: Only output for symbolic links. Contains flags from the `REPARSE_DATA_BUFFER` structure (e.g., `SYMLINK_FLAG_RELATIVE` = 0x1 indicates a relative symlink).

## Example Output

### JSON Format

**Hard Link Creation:**
```json
{"Plugin":"linkmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":5678,"TID":4321,"UserId":1,"ProcessName":"cmd.exe","FileName":"\\Device\\HarddiskVolume2\\Users\\Admin\\link.txt","LinkType":"hardlink","LinkTarget":"\\Device\\HarddiskVolume2\\Users\\Admin\\original.txt"}
```

**Symbolic Link Creation:**
```json
{"Plugin":"linkmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":5678,"TID":4321,"UserId":1,"ProcessName":"cmd.exe","FileName":"\\Device\\HarddiskVolume2\\Users\\Admin\\symlink.txt","LinkType":"symlink","Flags":"0x0","LinkTarget":"\\??\\C:\\Users\\Admin\\target.txt"}
```

**Junction Point Creation:**
```json
{"Plugin":"linkmon","TimeStamp":"1234567890.123456","PID":1234,"PPID":5678,"TID":4321,"UserId":1,"ProcessName":"cmd.exe","FileName":"\\Device\\HarddiskVolume2\\Users\\Admin\\junction","LinkType":"junction","LinkTarget":"\\??\\C:\\TargetDirectory"}
```

## Technical Details

The plugin works by:

1. Loading the ole32.dll JSON profile to obtain structure member offsets for:
   - `_FILE_LINK_INFORMATION` (RootDirectory, FileName, FileNameLength)
   - `_REPARSE_DATA_BUFFER` (ReparseTag, SymbolicLinkReparseBuffer, MountPointReparseBuffer, SubstituteNameOffset, SubstituteNameLength, PathBuffer, Flags)

2. Hooking `NtSetInformationFile` to intercept hard link creation:
   - Checks if `FileInformationClass` is `FileLinkInformation` (0xB)
   - Reads the target file handle and new link name from the `FILE_LINK_INFORMATION` structure

3. Hooking `NtFsControlFile` to intercept reparse point creation:
   - Checks if `FsControlCode` is `FSCTL_SET_REPARSE_POINT` (0x900A4)
   - Reads the `ReparseTag` to determine if it's a symlink or junction
   - Parses the appropriate buffer structure to extract the target path

When any of the hooked functions are called with the monitored parameters, the callback logs the event with the link details and process context information.
