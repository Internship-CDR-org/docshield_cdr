# DocShield Testing & Verification Guide

## 1. Testing Philosophy

DocShield adheres to strict standards for automated test design:
1. **Zero Dependency on Personal Files**: No tests rely on personal resumes, syllabi, admit cards, or developer-specific local files.
2. **Deterministic Synthetic Fixtures**: Tests construct clean, weaponized, or malformed fixtures in-memory or in ephemeral `@TempDir` workspaces.
3. **Cross-Platform Compatibility**: Subprocess and script mock tests run transparently on Windows, Linux, and macOS without requiring specific host shell configurations.
4. **Comprehensive Surface Coverage**: Unit and integration tests validate the entire lifecycle: identification, parsing, threat detection, sanitization, reconstruction, integrity validation, sandboxing, and quarantine.

---

## 2. Running Tests

### Standard Test Execution
```bash
mvn clean test
```

### Running a Specific Test Class
```bash
mvn test -Dtest=FileIdentifierComprehensiveTest
```

### Running with Debug Logging
```bash
mvn test -X
```

---

## 3. Test Suite Inventory

| Test Category | Test Class | Coverage Description |
|---|---|---|
| **Format Identification** | `FileIdentifierComprehensiveTest` | PDF, RTF (with/without BOM), DOCX, PPTX, XLSX identification, extension mismatch, and invalid file rejection. |
| | `FileIdentifierRTFTest` | RTF header detection and validation. |
| **Parsing & Model** | `DOCXParserIRTest` | DOCX structural parsing into Intermediate Representation. |
| | `OOXMLPackageReaderEmbeddedOOXMLTest` | Parsing embedded OOXML packages without disk materialization. |
| | `OOXMLPackagePPTXRoundTripTest` | PPTX package serialization and deserialization integrity. |
| | `TestTextComponent` | Text component data model validation. |
| | `TestHyperlinkComponent` | Hyperlink component data model validation. |
| **Security & Sandbox** | `PathSandboxTest` | Directory traversal, Zip Slip attacks, absolute paths, null bytes, and colon streams. |
| | `SecureXmlFactoryTest` | XXE protection, DOCTYPE disallowance, and entity expansion blocking. |
| | `SubprocessSandboxTest` | Bubblewrap capability probing, command wrapping, process timeouts, and cross-platform execution. |
| | `QuarantineManagerTest` | Quarantine directory isolation, SHA-256 recording, and audit notes. |
| **Threat Analyzers** | `DOCXSecuritySurfaceTest`, `DOCXThreatAnalyzerTest` | Word DDE, macros, ActiveX, and malicious XML detection. |
| | `PPTXSecuritySurfaceTest`, `PPTXThreatCoverageTest` | PowerPoint `ppaction://` triggers, OLE payloads, and dangerous SVG detection. |
| | `XLSXSecuritySurfaceTest`, `XLSXThreatAnalyzerTest`, `XLSXHardeningRegressionTest` | Excel XLM macros, active formulas (`RTD`, `CALL`, `WEBSERVICE`), and external workbooks. |
| | `PDFPass2SecurityTest`, `PDFSecurityPolicyTest`, `PDFSecuritySurfaceVerifierTest`, `PDFStreamThreatInspectorTest` | PDF JavaScript, OpenAction, Launch, XFA, and executable payload detection. |
| | `RTFThreatAnalyzerTest` | RTF template injection, Equation Editor exploits, and DDE detection. |
| | `LegacyOfficeThreatAnalyzerTest` | Legacy DOC/PPT/XLS raw OLE inspection. |
| **Sanitizers & Processors** | `OOXMLThreatSanitizerTest`, `RecursiveOOXMLSanitizerTest` | Multi-layer OOXML sanitization and nested package disarming. |
| | `DOCXThreatSanitizerTest`, `PPTXThreatSanitizerTest`, `XLSXThreatSanitizerTest` | Format-specific OOXML disarming. |
| | `PDFThreatSanitizerTest`, `PDFCDRProcessorTest`, `PDFCleanCopySha256Test` | PDF sanitization, stream disarming, and clean copy SHA-256 preservation. |
| | `RTFThreatSanitizerTest`, `RTFCDRProcessorTest`, `RTFIntegrityValidatorTest` | RTF disarming, group balance verification, and semantic re-parsing. |
| | `DOCToDOCXConverterTest`, `LegacyOfficeConverterTest` | Isolated legacy Office conversion, timeout handling, and output limit enforcement. |
| **Application & CLI** | `MainCliIntegrationTest` | End-to-end CLI workflow, clean PDF handling, and SHA-256 verification. |
| | `UserFacingErrorTest` | Operator-facing error message formatting and root-cause extraction. |
