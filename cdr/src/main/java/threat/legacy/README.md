# Legacy Office Threat Analysis (`threat.legacy`)

## Overview

The `threat.legacy` package provides structural, non-executing security inspection for legacy binary Microsoft Office documents (**Word `DOC`**, **PowerPoint `PPT`**, and **Excel `XLS`**).

---

## Why Legacy Documents are Inspected BEFORE Conversion

Legacy binary files are structured as OLE2 Compound Document files. When an untrusted legacy file is converted to modern OOXML (e.g., via LibreOffice in a sandbox), the converter often strips or fails to translate malicious macros, interactive actions, or DDE pipes into the resulting OOXML structure.

If DocShield only inspected the converted OOXML file, it would incorrectly report the original threat as "absent", giving a false impression that the source document was benign.

Therefore, DocShield executes [`LegacyOfficeThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/legacy/LegacyOfficeThreatAnalyzer.java) **directly on the legacy binary file first**, cataloging all pre-existing threats before initiating sandboxed conversion.

---

## Key Classes

### [`LegacyOfficeThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/legacy/LegacyOfficeThreatAnalyzer.java)
- **Path**: `src/main/java/threat/legacy/LegacyOfficeThreatAnalyzer.java`
- **Capabilities**:
  - **OLE Storage Traversal**: Scans OLE2 directories and streams using Apache POI `POIFSFileSystem` for VBA projects (`vba`, `macros`, `_vba_project`, `dir`, `project`, `projectwm`).
  - **PPT Interactive Atom Detection**: Scans binary PPT streams for `InteractiveInfoAtom` records (`0x0FF3`) capable of launching external programs or executing macros upon mouse click/hover.
  - **Script / Command String Scanning**: Inspects raw binary strings for command-line execution indicators (`powershell.exe`, `-encodedcommand`, `invoke-expression`, `wscript.shell`).
  - **XLS Formula & DDE Scanning**: Uses `HSSFWorkbook` (and fallback binary regex matching `XLS_DDE_FORMULA`) to identify DDE formula pipes (e.g., `cmd.exe!...`, `powershell.exe!...`).

---

## Threat Detection Coverage Table

| Threat / Capability | Detection Class | Evidence Checked | Classification & Severity | Blocking? | Sanitized? |
|---|---|---|---|---|---|
| **Legacy VBA Macro Project** | `LegacyOfficeThreatAnalyzer` | OLE storage/stream named `vba`, `macros`, `_vba_project`, `dir`, `project` | `THREAT` / `HIGH` | **YES** | **YES** (disarmed during sandboxed conversion + modern CDR) |
| **Legacy PPT Interactive Action** | `LegacyOfficeThreatAnalyzer` | Binary record type `0x0FF3` (`InteractiveInfoAtom`) in PPT stream | `THREAT` / `CRITICAL` | **YES** | **YES** (disarmed during sandboxed conversion + PPTX CDR) |
| **Legacy Script / Command Execution** | `LegacyOfficeThreatAnalyzer` | `powershell.exe`, `-encodedcommand`, `invoke-expression`, `wscript.shell` | `THREAT` / `CRITICAL` | **YES** | **YES** (disarmed during sandboxed conversion + modern CDR) |
| **Legacy XLS DDE Formula** | `LegacyOfficeThreatAnalyzer` | `HSSFCell` formula containing `DDE` or binary command pipe matching `XLS_DDE_FORMULA` | `THREAT` / `CRITICAL` | **YES** | **YES** (disarmed during sandboxed conversion + XLSX CDR) |
