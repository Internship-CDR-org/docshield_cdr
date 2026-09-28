# DocShield Security Model

## 1. Security Tenets

1. **Zero Trust File Ingestion**: Every input document is assumed to be adversary-controlled and potentially weaponized.
2. **Capability-Based Neutralization**: Detection focuses on active capabilities rather than brittle malware signatures or byte patterns.
3. **Clean-Path Byte Identity Preservation**: If an input is verified to contain zero blocking findings, the document is copied byte-for-byte to preserve its cryptographic hash and original signatures.
4. **Surgical Sanitization with Visual Preservation**: Threat components are neutralized while retaining benign document layout, styling, text, images, and non-dangerous links.
5. **Fail-Closed Guarantee**: Any failure during parsing, sanitization, reconstruction, or integrity verification results in immediate abort, partial output cleanup, quarantine isolation, and non-zero exit code.
6. **No Partial Output Exposure**: Output files are written to ephemeral staging paths and atomically moved into place only after passing all verification stages.

---

## 2. Threat Classification & Severity Matrix

DocShield categorizes security findings into four distinct classifications:

| Classification | Meaning | Action Taken |
|---|---|---|
| **THREAT** | Confirmed weaponized capability (VBA macro, executable payload, DDE injection, dangerous PDF action, XXE attempt). | Sanitized during reconstruction; fails closed if unremovable. |
| **POLICY_VIOLATION** | Prohibited capability violating security policy (external template, active XFA form, uninspected embedded package). | Neutralized or removed; fails closed if unremovable. |
| **SUSPICIOUS** | Anomalous structure (unsupported embedded format, obfuscated URI scheme, anomalous relationship). | Subject to quarantine or sanitized. |
| **OBSERVATION** | Informational discovery (benign HTTPS hyperlink, standard image, core metadata). | Documented in audit log; document preserved unmodified. |

---

## 3. Defense Against Common Exploit Vectors

### 3.1 Zip Slip & Archive Path Traversal
- Entry names are strictly checked against directory traversal (`..`, `../`, `..\`), absolute paths (`/`, `\`, drive letters), colon streams (`::$DATA`), and null bytes before decompression.
- Extraction uses path normalization and jail boundary checks (`PathSandbox.resolveSafe`).

### 3.2 Zip Bombs & Resource Exhaustion
- Bounded package processing limits:
  - Max ZIP entries: 10,000
  - Max single part size: 128 MB
  - Max uncompressed total package size: 256 MB
  - Max recursive embedded depth: 4 levels
  - Max embedded packages: 256

### 3.3 XML Entity Injection (XXE) & Billion Laughs
- All XML parsers are created via `SecureXmlFactory`:
  - `FEATURE_SECURE_PROCESSING = true`
  - `disallow-doctype-decl = true`
  - `external-general-entities = false`
  - `external-parameter-entities = false`
  - `load-external-dtd = false`
  - `ACCESS_EXTERNAL_DTD = ""`
  - `ACCESS_EXTERNAL_SCHEMA = ""`

### 3.4 Dynamic Data Exchange (DDE) & Command Execution
- Word field instructions (`DDE`, `DDEAUTO`) are parsed across run boundaries and removed while preserving cached calculation results.
- Excel formulas referencing DDE channels or command pipes (`cmd|...`, `powershell|...`) are sanitized and cached result values are cleared.
- RTF `\field` groups with `DDE` / `DDEAUTO` are stripped to static text.

### 3.5 VBA Macros & XLM 4.0 Macros
- Macro parts (`vbaProject.bin`, `macroEnabled` parts) and XLM macrosheets are removed from OOXML packages.
- Corresponding relationship definitions, content-type overrides, and menu/ribbon customizations are purged.

### 3.6 PDF Active Content
- JavaScript engines, `/OpenAction`, `/Launch`, `/GoToR`, `/GoToE`, `/SubmitForm`, `/ImportData`, `/XFA`, and arbitrary `/EmbeddedFiles` are stripped from the COS catalog and page object graphs.
- Decoded stream bytes are inspected for executable headers (`MZ`, `ELF`, `Mach-O`, shell scripts) and cleared.

### 3.7 Output Staging & Atomic Movement
- Reconstructed files are written to ephemeral temporary files and atomically moved (`StandardCopyOption.ATOMIC_MOVE`) to the target destination only after completing serialization.
- If an exception occurs, any partial temporary file is immediately purged.
