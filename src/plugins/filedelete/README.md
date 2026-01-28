# Filedelete Plugin

## Overview

The filedelete plugin monitors and extracts files that are being deleted or modified within a Windows guest VM. It intercepts Windows NT kernel functions related to file operations and can optionally extract the file contents before they are deleted or closed after modification.

The plugin works by hooking into key Windows system calls:
- **NtSetInformationFile** - Detects files marked for deletion via `FileDispositionInformation`
- **NtWriteFile** - Tracks files that are being written to
- **NtClose** - Intercepts file handle closure to extract file contents before deletion
- **NtCreateFile/NtOpenFile** - Detects files opened with `FILE_DELETE_ON_CLOSE` flag
- **ZwCreateSection** - Tracks files mapped with write access

When a tracked file handle is closed, the plugin extracts the file contents either through direct memory reading from the Windows memory manager structures (control areas, subsections, PTEs) or through function injection that uses Windows kernel APIs to read the file.

## Supported Operating Systems

**Windows only** - This plugin is designed specifically for Windows guests and relies on Windows kernel structures and NT API functions. It does not support Linux guests.

## Configuration Options

The plugin accepts the following configuration options:

| Option | Command Line | Description |
|--------|--------------|-------------|
| `dump_folder` | `-D <folder>` | Directory where extracted files will be saved. Required for file extraction. |
| `dump_modified_files` | `-M` | When enabled, also dumps files that have been modified (not just deleted). Requires `-D`. |
| `filedelete_use_injector` | `-n` | Use function injection method for file extraction instead of direct memory reading. Requires `-D`. |

### Extraction Methods

1. **Direct Memory Reading (default)**: Reads file contents directly from Windows memory manager structures by walking control areas and subsections. This method hooks `NtSetInformationFile`, `NtWriteFile`, and `NtClose`.

2. **Function Injection (`-n` flag)**: Injects Windows kernel API calls into the guest to read file contents. This method additionally hooks `ZwCreateSection`, `NtCreateFile`, and `NtOpenFile`. It uses:
   - `ZwQueryVolumeInformationFile` - Get volume/device information
   - `ZwQueryInformationFile` - Get file size
   - `ZwCreateSection` - Create a memory section for the file
   - `ZwMapViewOfSection` - Map the section into memory
   - `RtlCopyMemoryNonTemporal` - Copy file contents
   - `ZwUnmapViewOfSection` - Unmap the view
   - `ZwClose` - Close the section handle

## How to Enable the Plugin

### Build Configuration (Meson)

The plugin is disabled by default. Enable it during the build configuration:

```bash
meson setup build -Dplugin-filedelete=true
```

Or reconfigure an existing build:

```bash
meson configure build -Dplugin-filedelete=true
```

### Runtime Options

```bash
# Basic usage - just log file deletion events
drakvuf -r <rekall_profile> -d <domain>

# Extract deleted files to a folder
drakvuf -r <rekall_profile> -d <domain> -D /path/to/dump/folder

# Also extract modified files
drakvuf -r <rekall_profile> -d <domain> -D /path/to/dump/folder -M

# Use function injection for extraction
drakvuf -r <rekall_profile> -d <domain> -D /path/to/dump/folder -n
```

## Output Format

### Console Output

The plugin outputs events with the plugin name `fileextractor` for successful extractions and `fileextractor_fail` for failures.

#### Successful Extraction Fields

| Field | Type | Description |
|-------|------|-------------|
| `FileName` | String | Full path of the file being extracted |
| `Size` | Number | Size of the extracted file in bytes |
| `Flags` | Hex | Raw file object flags value |
| `FlagsExpanded` | String | Human-readable file object flags |
| `SeqNum` | Number | Sequence number for this extraction |
| `Reason` | String | Either "WriteFile" (modified file) or "DeleteFile" (deleted file) |

#### File Object Flags

The `FlagsExpanded` field may contain combinations of:
- `FO_FILE_OPEN` - File is open
- `FO_SYNCHRONOUS_IO` - Synchronous I/O
- `FO_FILE_MODIFIED` - File has been modified
- `FO_FILE_SIZE_CHANGED` - File size changed
- `FO_DELETE_ON_CLOSE` - File marked for deletion on close
- `FO_TEMPORARY_FILE` - Temporary file
- And others as defined in Windows

#### Extraction Failure Fields

| Field | Type | Description |
|-------|------|-------------|
| `FileName` | String | Full path of the file that failed to extract |
| `Message` | String | Error message describing the failure |

### Saved Files

When a dump folder is specified (`-D`), the plugin saves:

1. **File data**: `file.NNNNNN.mm` - Raw file contents
2. **Metadata**: `file.NNNNNN.metadata` - JSON file with extraction details

#### Metadata File Contents

```json
{
  "FileName": "\\Device\\HarddiskVolume1\\path\\to\\file.txt",
  "FileSize": 1234,
  "FileFlags": "0x12000 (FO_FILE_MODIFIED|FO_DELETE_ON_CLOSE)",
  "SequenceNumber": 1,
  "ControlArea": "0xffff8a8012345678",
  "PID": 1234,
  "PPID": 5678,
  "ProcessName": "malware.exe",
  "FullReadSuccess": true
}
```

If extraction was only partially successful:
```json
{
  "FullReadSuccess": false,
  "ReadNTStatus": 3221225566
}
```

## Example Output

### Default Format
```
fileextractor Time=1234567890 PID=1234 PPID=5678 TID=4321 UserName="SYSTEM" UserId=0 ProcessName="malware.exe" Method="NtClose" FileName="\Device\HarddiskVolume1\Users\test\AppData\Local\Temp\evil.dll" Size=45056 Flags=0x12000 FlagsExpanded="FO_FILE_MODIFIED|FO_DELETE_ON_CLOSE" SeqNum=1 Reason="DeleteFile"
```

### JSON Format
```json
{
  "Plugin": "fileextractor",
  "TimeStamp": "1234567890",
  "PID": 1234,
  "PPID": 5678,
  "TID": 4321,
  "UserName": "SYSTEM",
  "UserId": 0,
  "ProcessName": "malware.exe",
  "Method": "NtClose",
  "FileName": "\\Device\\HarddiskVolume1\\Users\\test\\AppData\\Local\\Temp\\evil.dll",
  "Size": 45056,
  "Flags": "0x12000",
  "FlagsExpanded": "FO_FILE_MODIFIED|FO_DELETE_ON_CLOSE",
  "SeqNum": 1,
  "Reason": "DeleteFile"
}
```

### Failure Output
```
fileextractor_fail Time=1234567890 PID=1234 PPID=5678 TID=4321 ProcessName="malware.exe" FileName="\Device\HarddiskVolume1\path\to\file.txt" Message="ZwCreateSection failed with status 0xc0000034"
```
