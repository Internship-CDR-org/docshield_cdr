# DocShield Architecture Specification

## 1. System Overview

DocShield is a high-assurance Content Disarm and Reconstruction (CDR) engine built on Java 21. Its objective is to disarm active, weaponized, or evasive content in incoming document formats (PDF, DOCX, PPTX, XLSX, RTF, DOC, PPT, XLS) while preserving valid document structures, content, layout, and visual fidelity.

```
+-------------------------------------------------------------------------+
|                              DocShield CDR                              |
+-------------------------------------------------------------------------+
                                    |
                            [ Input Document ]
                                    |
                                    v
                     +-----------------------------+
                     |    Format Identification    |
                     |     & Extension Matching    |
                     +-----------------------------+
                                    |
        +---------------------------+---------------------------+
        |                                                       |
  [Legacy Formats]                                        [Modern Formats]
   (DOC, PPT, XLS)                                     (DOCX, PPTX, XLSX, PDF, RTF)
        |                                                       |
        v                                                       v
+-------------------------------+                     +-------------------+
|  Pre-Conversion Inspection    |                     |  Secure In-Memory |
| (OLE / BIFF8 / Macro Analysis)|                     |      Parsing      |
+-------------------------------+                     +-------------------+
        |                                                       |
        v                                                       v
+-------------------------------+                     +-------------------+
| Sandboxed LibreOffice Convert |                     |   Threat & Policy |
|  (Isolated Ephemeral Process) |                     |      Analysis     |
+-------------------------------+                     +-------------------+
        |                                                       |
        +-------------------> [ DOCX/PPTX/XLSX ]                |
                                    |                           |
                                    +---------------------------+
                                                                |
                                                                v
                                                      +-------------------+
                                                      |   Clean Check?    |
                                                      +-------------------+
                                                       /                 \
                                              [Clean] /                   \ [Threat / Policy]
                                                     /                     \
                                                    v                       v
                                        +--------------------+    +--------------------+
                                        | Byte-for-Byte Copy |    | Surgical Disarm /  |
                                        | (SHA-256 Identity) |    | Sanitization Layer |
                                        +--------------------+    +--------------------+
                                                    |                       |
                                                    |                       v
                                                    |             +--------------------+
                                                    |             |   Reconstruction   |
                                                    |             |  & Serialization   |
                                                    |             +--------------------+
                                                    |                       |
                                                    |                       v
                                                    |             +--------------------+
                                                    |             |   Post-CDR Re-Read |
                                                    |             | & Integrity Check  |
                                                    |             +--------------------+
                                                    |                       |
                                                    |                       v
                                                    |             +--------------------+
                                                    |             | Multi-Pass Security|
                                                    |             |    Verification    |
                                                    |             +--------------------+
                                                    |                       |
                                                    +-----------+-----------+
                                                                |
                                                                v
                                                      +-------------------+
                                                      | Output Generation |
                                                      | & Audit Reporting |
                                                      +-------------------+
```

---

## 2. Core Pipelines

### 2.1 Modern OOXML Pipeline (`DOCX`, `PPTX`, `XLSX`)
1. **Package Ingest (`OOXMLPackageReader`)**:
   - Parses ZIP entries using strict Zip Slip prevention (`PathSandbox.assertSafeZipEntry`).
   - Validates total uncompressed size (<= 256 MB), part count (<= 10,000), single-part size (<= 128 MB).
   - Validates XML parts and relationship files against XXE injection using hardened parser settings (`SecureXmlFactory`).
2. **Threat Analysis (`OOXMLThreatAnalyzer`, `DOCXThreatAnalyzer`, `PPTXThreatAnalyzer`, `XLSXThreatAnalyzer`)**:
   - Scans for VBA projects, ActiveX controls, OLE objects, external relationships, suspicious URIs, DDE fields/formulas, dangerous PowerPoint actions (`ppaction://`), dynamic macros, external workbooks, and entity declarations.
3. **Clean-Path Fast Track**:
   - If zero blocking findings are detected, the input file is copied directly byte-for-byte to the destination, and SHA-256 identity is strictly verified.
4. **Sanitization (`OOXMLThreatSanitizer`, `RecursiveOOXMLSanitizer`)**:
   - Strips malicious XML elements, removes dangerous relationship attributes, neutralizes DDE and active formulas while preserving visible text/cells.
   - Recursively unpacks embedded OOXML packages (up to depth 4) to disarm nested threats.
5. **Reconstruction (`OOXMLPackageWriter`)**:
   - Rebuilds fresh `[Content_Types].xml` and relationship `.rels` files, omitting sanitized or orphaned components.
6. **Integrity Validation & Multi-Pass Loop (`OOXMLIntegrityValidator`)**:
   - Re-reads output from disk, validates package graph consistency, and re-analyzes for residual findings up to 3 passes.

### 2.2 PDF Pipeline (`PDFCDRProcessor`)
1. **PDFBox Ingestion**: Loads document with PDFBox 3.x in non-executing mode.
2. **Threat Analysis (`PDFThreatAnalyzer`, `PDFEmbeddedPayloadInspector`, `PDFStreamThreatInspector`)**:
   - Identifies JavaScript actions (`/JS`, `/JavaScript`), `/OpenAction`, `/Launch`, `/GoToR`, `/GoToE`, `/SubmitForm`, `/ImportData`, `/XFA`, `/RichMedia`, `/3D`, and executable signatures in raw decoded streams.
3. **Sanitization (`PDFThreatSanitizer`)**:
   - Strips dangerous action dictionaries, neutralizes embedded files, removes signature fields, and purges executable streams.
4. **Two-Stage Atomic Serialization**:
   - Writes to a temporary `.tmp` file in destination folder before atomically moving to final output path to prevent partial output exposure.
5. **Integrity & Security Surface Verification (`PDFIntegrityValidator`, `PDFSecuritySurfaceVerifier`)**:
   - Re-opens written PDF, verifies page rendering structures, catalog, and names trees.

### 2.3 RTF Pipeline (`RTFCDRProcessor`)
1. **Structural Identification & Validation**: Validates `{\rtf` header, optional UTF-8 BOM, and balanced brace depth.
2. **Threat Analysis (`RTFThreatAnalyzer`)**: Scans for embedded OLE objects (e.g. Equation Editor exploits), template injections (`\template`), DDE/DDEAUTO fields, and dangerous URL schemes.
3. **Surgical Disarm (`RTFThreatSanitizer`)**: Removes active constructs while extracting preview images or cached static text from `\result` / `\fldrslt`.
4. **Integrity Validation (`RTFIntegrityValidator`)**: Verifies reconstructed RTF parses cleanly with semantic parser.

### 2.4 Legacy Office Pipeline (`DOCCDRProcessor`, `PPTCDRProcessor`, `XLSCDRProcessor`)
1. **Pre-Conversion Security Inspection**:
   - Raw OLE2 compound file analysis (`DOCThreatAnalyzer`, `LegacyOfficeThreatAnalyzer`) identifies VBA macro streams, BIFF8 formulas, and action atoms before external processing.
2. **Subprocess Isolation (`LegacyOfficeConverter`, `SubprocessSandbox`)**:
   - Spawns LibreOffice in headless mode inside an ephemeral workspace with dedicated user profile directory.
   - Governed by process timeout, memory limits, and output disk-quota monitoring.
3. **Modern Pipeline Handoff**:
   - Output DOCX/PPTX/XLSX is routed through the modern OOXML CDR pipeline.
4. **Audit Aggregation & Workspace Cleanup**:
   - Pre-conversion legacy findings are merged into the final CDR report.
   - The entire temporary workspace is wiped recursively.

---

## 3. Sandboxing & Isolation Architecture

- **Path Sandboxing (`PathSandbox`)**:
  - Enforces filesystem jail boundaries to prevent directory traversal and symlink escapes.
- **Secure XML Factory (`SecureXmlFactory`)**:
  - Disallows DOCTYPE declarations, external general/parameter entities, and external DTD/schema loading.
- **Subprocess Isolation (`SubprocessSandbox`)**:
  - Probes Bubblewrap (`bwrap`) capability using real namespace isolation probe before enabling sandboxing.
  - Enforces background disk quota polling (every 250ms) and recursive process-tree termination upon timeout or limit violation.
