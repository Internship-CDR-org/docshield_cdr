# DocShield Limitations & Operational Boundaries

DocShield is engineered to provide deterministic, high-assurance Content Disarm & Reconstruction (CDR) across OOXML (`.docx`, `.pptx`, `.xlsx`), PDF, RTF, and legacy Microsoft Office binary formats (`.doc`, `.ppt`, `.xls`). To maintain maximum transparency and operational clarity for security engineers and administrators, this document outlines the intentional boundaries, known constraints, and non-goals of DocShield.

---

## 1. Intentional Security Boundaries & Non-Goals

### 1.1 Lossy Active-Content Stripping
- **Macros and VBA Scripts**: DocShield enforces a strict zero-trust disarm policy for macro content. Macros, VBA projects (`vbaProject.bin`), and ActiveX controls are stripped without execution or dynamic analysis. If a business workflow relies on executing embedded VBA macros, reconstructed documents will no longer contain active script logic.
- **Embedded Executable Payloads & OLE Packages**: All native executables (`.exe`, `.dll`, `.bat`, `.cmd`, `.vbs`, `.ps1`, `.scr`, `.elf`, etc.) embedded within document packages or OLE streams are removed or converted to neutralized placeholder tokens.
- **Dynamic Calculation / Formula Injections**: DDE commands and suspicious external spreadsheet links are sanitized. Formula evaluation semantics that attempt OS process invocation are disabled.

### 1.2 Encrypted & Password-Protected Documents
- DocShield requires access to the structural contents of files to perform parsing, threat analysis, sanitization, and reconstruction.
- Documents protected with AES/RC4 standard passwords (encrypted ZIP containers or encrypted PDF streams) cannot be inspected without keys. DocShield fails closed on encrypted files (`CDRProcessingException` / `SecurityInspectionException`), quarantines or rejects the file, and does not attempt brute-force decryption.

### 1.3 Not an Antivirus or Signature-Based Scanner
- DocShield operates on **structural content disarm and positive reconstruction** principles, not signature detection (e.g., YARA or AV heuristic signatures).
- It eliminates the structural vectors through which exploits trigger (active scripts, parser differentials, stream corruptions, launch actions), rather than detecting specific malware families.

### 1.4 Optical Character Recognition (OCR) and Pixel-Level Steganography
- DocShield inspects image metadata and removes dangerous payload-bearing markers (e.g., polyglot headers, embedded scripts).
- It does not run OCR on raster images to detect textual phishing embedded within screenshots, nor does it perform deep frequency-domain cryptanalysis to detect image steganography.

---

## 2. Platform & Environment Constraints

### 2.1 Subprocess Sandbox Requirements (Bubblewrap)
- Strong OS-level sandboxing for legacy conversions uses Bubblewrap (`bwrap`) on Linux.
- **Kernel Namespace Dependency**: Bubblewrap relies on unprivileged user namespaces (`CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
- **Capability Probe**: DocShield probes the actual capability of `bwrap` at startup. If running in a container or Linux host where user namespaces are restricted, DocShield logs a warning and falls back to strictly monitored subprocess execution with process timeouts, bounded memory, and unprivileged user execution.
- On Windows and macOS, OS sandboxing falls back to monitored process timeouts, working directory isolation, and environment sanitization.

### 2.2 Legacy Binary Conversion Dependency (LibreOffice)
- Modern OOXML (`.docx`, `.pptx`, `.xlsx`), `.pdf`, and `.rtf` are parsed and reconstructed directly in pure Java without third-party desktop office dependencies.
- Legacy binary formats (`.doc`, `.ppt`, `.xls`) require an external headless LibreOffice instance (`soffice --headless`) within an isolated subprocess for format modernization to OOXML.
- If LibreOffice is not installed, legacy binary files will fail closed during the conversion stage.

---

## 3. Format-Specific Constraints

### 3.1 PDF Structural Rebuilding
- DocShield uses Apache PDFBox to disarm PDF files by systematically neutralizing `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, `/SubmitForm`, and unverified URI schemes, followed by structural object re-indexing.
- Complex interactive AcroForms with dynamic script calculations are flattened or stripped of active event hooks.

### 3.2 OOXML Visual Fidelity
- DocShield parses and rebuilds Open Packaging Conventions (OPC) archives using secure XML parsers and Apache POI.
- Document text, tables, styles, bullet points, charts, shapes, drawing elements, and media streams are preserved. Extremely obscure vendor-proprietary XML markup extensions (non-standard schema extensions) may be omitted if they fail schema validation.

### 3.3 Large File Handling
- To prevent Denial of Service via Resource Exhaustion (Zip Bombs, Billion Laughs, deeply nested XML, unbounded decompressed streams), DocShield enforces strict limits:
  - Maximum package entry count: 10,000 entries
  - Maximum individual entry size: 250 MB
  - Maximum total uncompressed size: 500 MB
  - Maximum compression ratio: 100:1
  - Maximum XML depth: 50 levels
- Inputs exceeding these limits fail closed immediately with a `ZipBombException` or `ResourceLimitException`.

---

## 4. Summary

DocShield provides maximum security through deterministic content disarm. It guarantees that released files are structurally valid, free of active execution primitives, and byte-identical to the original if no threats were detected. For automated pipeline integrations, ensure that LibreOffice is available if legacy binary support is required and configure system limits according to your enterprise throughput needs.
