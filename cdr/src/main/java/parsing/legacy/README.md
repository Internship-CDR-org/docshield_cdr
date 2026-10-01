# Legacy Office Conversion Subsystem (`parsing.legacy`)

The `parsing.legacy` package implements the secure boundary for converting untrusted legacy Microsoft Office binary formats (`DOC`, `PPT`, `XLS`) into modern Open Packaging Conventions (OPC / OOXML) documents (`DOCX`, `PPTX`, `XLSX`).

---

## 1. Architectural Purpose: The Sandboxed Conversion Boundary

Legacy Office files (Word 97-2003, PowerPoint 97-2003, Excel 97-2003) use proprietary, complex binary structures (OLE2 Compound File Binary Format / BIFF8). In-process parsing of untrusted legacy binaries presents a high risk of memory corruption vulnerabilities and parser exploitation.

DocShield strictly isolates legacy processing:
1. **Pre-Conversion Threat Analysis**: Input binaries are analyzed first by dedicated legacy analyzers ([`DOCThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/doc/DOCThreatAnalyzer.java), [`PPTThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ppt/PPTThreatAnalyzer.java), [`XLSThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/xls/XLSThreatAnalyzer.java)) to catalog any active macros, OLE objects, or DDE links.
2. **Hardened Out-of-Process Conversion**: The document is converted to modern OOXML via an isolated LibreOffice instance orchestrated by [`LegacyOfficeConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/legacy/LegacyOfficeConverter.java) and [`SubprocessSandbox`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/sandbox/SubprocessSandbox.java).
3. **Downstream Modern CDR**: The converted OOXML package is subsequently processed by modern CDR engines (`DOCXCDRProcessor`, `PPTXCDRProcessor`, `XLSXCDRProcessor`).

---

## 2. Core Implementation: `LegacyOfficeConverter`

[`LegacyOfficeConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/legacy/LegacyOfficeConverter.java) is the shared, hardened execution driver for legacy conversions.

### Key Security Controls

1. **System Properties & Limits**:
   - `docshield.libreoffice.command` (default: `"libreoffice"`)
   - `docshield.libreoffice.timeout.seconds` (default: `60` seconds)
   - `docshield.libreoffice.max.input.bytes` (default: `200 MB` / `209,715,200` bytes)
   - `docshield.libreoffice.max.output.bytes` (default: `200 MB` / `209,715,200` bytes)

2. **Isolated Workspace Lifecycle**:
   - Creates an ephemeral temporary directory (`docshield_legacy_conversion_*`).
   - Generates isolated `output/` and `profile/` subdirectories.
   - Sets LibreOffice user installation path to the ephemeral profile (`-env:UserInstallation=file://...`), preventing access to host user configuration or saved credentials.
   - Enforces headless mode flags: `--headless --nologo --nodefault --norestore --nolockcheck`.

3. **Subprocess Sandboxing (`SubprocessSandbox`)**:
   - Executes the conversion command through [`SubprocessSandbox.execute`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/sandbox/SubprocessSandbox.java).
   - Monitors the output directory every 250ms; terminates the entire process tree if output exceeds `maxOutputBytes`.
   - Terminates process tree if execution exceeds the timeout (`60s`).
   - Caps stdout/stderr capture at 64 KB to prevent buffer exhaustion.

4. **Output Verification & Atomic Handling**:
   - Confirms the converted file exists, is a regular file, is readable, has non-zero size, and does not exceed `maxOutputBytes`.
   - If conversion fails or returns a non-zero exit code, an `IOException` is raised with captured diagnostics, and the workspace is destroyed immediately.

---

## 3. Format Converters

The format-specific converter classes provide clean facade methods:
- [`DOCToDOCXConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/doc/DOCToDOCXConverter.java): Invokes `LegacyOfficeConverter.convert(file, "DOC", "docx")`.
- [`PPTToPPTXConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ppt/PPTToPPTXConverter.java): Invokes `LegacyOfficeConverter.convert(file, "PPT", "pptx")`.
- [`XLSToXLSXConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/xls/XLSToXLSXConverter.java): Invokes `LegacyOfficeConverter.convert(file, "XLS", "xlsx")`.
