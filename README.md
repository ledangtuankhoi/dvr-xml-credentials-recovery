# Generic CCTV XML Configuration Decryptor & Device Management Utility

A lightweight, zero-external-dependency utility written in PowerShell and Python to parse, inspect, and decrypt device export XML configurations and database profiles for embedded DVR/NVR surveillance devices.

---

## 🌟 Key Features & Purpose

- **Zero Third-Party Dependencies**: Pure native PowerShell implementation leveraging `.NET System.Security.Cryptography` and standard XML DOM parsers.
- **AES-128 Cryptographic Recovery**: Reconstructs plaintext device access credentials from Base64-encoded encrypted string attributes.
- **Binary Response Parsing**: Decodes nested Base64 binary payload fields (`<rsp>`) to inspect device hardware details, firmware versions, MAC addresses, and P2P registration IDs.
- **Dual Execution Modes**:
  - Direct PowerShell Script (`.ps1`) supporting XML files, strings, and pipeline input.
  - One-Click Windows Command Prompt Batch Script (`.cmd`) wrapper for quick drag-and-drop operation.
- **Database & Sync Tooling**: Python scripts for direct SQLite configuration table inspection and cross-device camera sync without XML exports.

---

## 🛠️ Cryptographic Architecture

The device export XML configuration employs an **AES-128-ECB** encryption scheme for credentials when `encode="1"` is specified:

- **Algorithm**: AES-128 (Electronic Codebook Mode)
- **Padding**: Zero-byte (`\x00`) padding to 16-byte block boundaries
- **Payload Format**: Base64-encoded 32-byte ciphertext (2 AES blocks)
- **PlainText Flag**: When `encode="0"`, the password value is stored directly in cleartext.

---

## 📁 Repository Structure

```
.
├── cctv_xml_decoder.ps1    # Core PowerShell parser & decryptor engine
├── cctv_xml_decoder.cmd    # Windows CMD wrapper for interactive file selection
├── cctv_db_tool.py         # Python SQLite database inspection & sync script
└── README.md               # Project documentation
```

---

## 🚀 Quick Start Guide

### Option 1: PowerShell Command Line

Pass an exported XML file directly:
```powershell
.\cctv_xml_decoder.ps1 -Path "C:\path\to\device_export.xml"
```

Parse an XML snippet directly:
```powershell
.\cctv_xml_decoder.ps1 -XmlString '<NO DeviceName="Camera1" encode="1" Password="..." IP="192.168.1.100" UserName="admin" MediaPort="9000" ChannelNum="16"></NO>'
```

### Option 2: Windows CMD / Batch Script

Double-click `cctv_xml_decoder.cmd` or run from Command Prompt:
```cmd
cctv_xml_decoder.cmd devices.xml
```

---

## 📋 XML Field Reference

The XML configuration format utilizes the `<NO>` tag for each device record:

| XML Attribute | Field Description | Example Value |
| :--- | :--- | :--- |
| `DeviceName` | User-defined device alias | `Building_A_DVR` |
| `encode` | Cryptographic status (`1` = Encrypted, `0` = Plaintext) | `1` |
| `Password` | Access credential (Base64 AES ciphertext or Plaintext) | `LJkriBRb...` |
| `IP` | P2P Cloud GID / IP Address / Domain | `A1CKP1JET2SLC43R111A` |
| `UserName` | Device login account | `admin` |
| `MediaPort` | Streaming media service port | `9000` |
| `ChannelNum` | Total supported video channels | `32` |
| `<rsp>` | Base64 encoded binary payload (Firmware / MAC / Serial) | `AQYwAAUD...` |

---

## 📄 License & Terms

Distributed for security auditing, backup, and device migration purposes. Free to modify and distribute under the MIT License.
