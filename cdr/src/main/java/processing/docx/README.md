# DOCX Processing Pipeline (`processing.docx`)

The `processing.docx` package contains the pipeline driver for Microsoft Word documents.

---

## 1. Pipeline Execution Flow (`DOCXCDRProcessor`)

[`DOCXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/docx/DOCXCDRProcessor.java) executes the following sequence:

1. **Hash Input**: Computes initial SHA-256 (`CDRFileUtil.sha256(inputFile)`).
2. **Read Package**: Ingests the OPC package into an in-memory [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) via [`OOXMLPackageReader`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ooxml/OOXMLPackageReader.java).
3. **Threat Analysis**: Runs [`DOCXThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/docx/DOCXThreatAnalyzer.java) to detect VBA macros, ActiveX, Word field DDE/DDEAUTO, dangerous hyperlinking, template attachments, `altChunk`, settings anomalies, and suspicious embedded payloads.
4. **Sanitization Pass**:
   - Executes [`DOCXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/docx/DOCXThreatSanitizer.java).
   - Executes [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) on embedded packages in memory.
5. **Clean Copy Check**:
   - If no blocking findings (`THREAT`, `POLICY_VIOLATION`, `SUSPICIOUS`) were discovered, performs a direct byte-for-byte copy via `CDRFileUtil.copyOriginal(inputFile, outputFile)`.
   - Asserts input SHA-256 matches output SHA-256 (`cleanCopy = true`).
6. **Reconstruction**:
   - If actionable threats were present, serializes the sanitized package to disk via [`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
7. **Bounded Hardening & Verification Loop (Up to 3 Passes)**:
   - Re-reads the serialized file from disk via `OOXMLPackageReader`.
   - Validates structural integrity via [`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java).
   - Re-analyzes with `DOCXThreatAnalyzer`.
   - Validates embedded content safety via `RecursiveOOXMLSanitizer.hasBlockingEmbeddedContent`.
   - If clean: breaks loop successfully.
   - If blocking findings remain and `pass < 3`: re-sanitizes, re-runs recursive sanitizer, and rewrites output to disk.
8. **Result Assembly**: Computes output SHA-256 and returns a comprehensive [`CDRResult`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRResult.java).
