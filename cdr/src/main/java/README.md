# Java Source Root (`src/main/java`)

This directory contains the root source tree of DocShield CDR.

---

## 1. Application Entry Point: `Main.java`

[`Main.java`](Main.java) is the CLI orchestrator and security gatekeeper.

### Command Line Interface
```bash
./scripts/sandbox-run.sh <input-file> <output-file>
```
Or directly via Java:
```bash
java -cp "$CLASSPATH" Main <input-file> <output-file>
```

### Exit Codes
- **`0`**: Successful processing. Either a clean copy was produced (with identical SHA-256) or the document was successfully sanitized, reconstructed, and verified.
- **`1`**: Operator or command-line usage error (invalid arguments, same input/output path, unreadable file, un-writable destination directory).
- **`2`**: Quarantine exit. The input file could not be safely identified, contained unremovable threats, failed integrity validation, encountered parser exceptions, or was an unsupported format. A timestamped quarantine record is preserved in `output/quarantine/`.

---

## 2. Decision Flow in `Main.java`

```
                      CLI Arguments (<input>, <output>)
                                     │
                                     ▼
                      1. Argument & Path Validation
                         (Ensure distinct, readable, non-empty)
                                     │
                                     ▼
                      2. Format Identification (FileIdentifier)
                         (Magic bytes, zip structures, anti-spoofing)
                                     │
              ┌──────────────────────┴──────────────────────┐
              ▼                                             ▼
       Unknown / Spoofed                             Valid Supported Format
              │                                             │
              ▼                                             ▼
       Quarantine & Exit (2)                         3. CDRProcessor Selection
                                                        • DOCX -> DOCXCDRProcessor
                                                        • PPTX -> PPTXCDRProcessor
                                                        • XLSX -> XLSXCDRProcessor
                                                        • DOC  -> DOCCDRProcessor
                                                        • PPT  -> PPTCDRProcessor
                                                        • XLS  -> XLSCDRProcessor
                                                        • PDF  -> PDFCDRProcessor
                                                        • RTF  -> RTFCDRProcessor
                                                            │
                                                            ▼
                                                     4. Execution (processor.process)
                                                            │
                                     ┌──────────────────────┴──────────────────────┐
                                     ▼                                             ▼
                              CDR Success                                     Exception / Failure
                                     │                                             │
                                     ▼                                             ▼
                       5. Verification Gates                                 Safe Delete Output
                          • isOutputReady()?                                       │
                          • isIntegrityPassed()?                                   ▼
                          • threatsRemoved()?                               Quarantine & Exit (2)
                                     │
                      ┌──────────────┴──────────────┐
                      ▼                             ▼
                    PASS                          FAIL
                      │                             │
                      ▼                             ▼
               6. Audit Reporting            Safe Delete Output
                  (ReportWriter)                    │
                      │                             ▼
                      ▼                      Quarantine & Exit (2)
               Release & Exit (0)
```

---

## 3. Subsystem Package Map

| Package | Role |
|---|---|
| [`identification`](identification\README.md) | Binary magic byte sniffing, OOXML ZIP probing, and extension-mismatch anti-spoofing verification. |
| [`parsing`](parsing\README.md) | Secure OOXML archive ingestion ([`OOXMLPackageReader`](parsing\ooxml\OOXMLPackageReader.java)), semantic IR extractors, and legacy conversion bridges. |
| [`threat`](threat\README.md) | Capability-based threat analyzers for OOXML, DOCX, PPTX, XLSX, legacy Office, and PDF. |
| [`sanitization`](sanitization\README.md) | Disarming engines for OPC package graphs, Word fields, PowerPoint actions, Excel formulas, and PDF objects. |
| [`reconstruction`](reconstruction\README.md) | Package serializer ([`OOXMLPackageWriter`](reconstruction\OOXMLPackageWriter.java)) dynamically rebuilding `[Content_Types].xml` and `.rels`. |
| [`validation`](validation\README.md) | Post-reconstruction structural integrity validators ([`OOXMLIntegrityValidator`](validation\ooxml\OOXMLIntegrityValidator.java), [`PDFIntegrityValidator`](validation\pdf\PDFIntegrityValidator.java)). |
| [`processing`](processing\README.md) | End-to-end format pipeline orchestrators, clean-copy optimizations, and bounded hardening loops. |
| [`security`](security\README.md) | Quarantine manager and isolation sandboxes ([`SubprocessSandbox`](security\sandbox\SubprocessSandbox.java), [`PathSandbox`](security\sandbox\PathSandbox.java), [`SecureXmlFactory`](security\sandbox\SecureXmlFactory.java)). |
| [`model`](model\README.md) | In-memory package models ([`OOXMLPackage`](model\ooxml\OOXMLPackage.java)) and semantic intermediate representations ([`DocumentModel`](model\common\DocumentModel.java)). |
| [`reporting`](reporting\README.md) | Formats detailed human-readable audit reports (`output/reports/*_CDR_Report.txt`). |
| [`application`](application\README.md) | Translates internal exceptions into user-friendly terminal and quarantine messages. |
