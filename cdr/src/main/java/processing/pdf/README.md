# PDF Processing Pipeline (`processing.pdf`)

The `processing.pdf` package contains the pipeline driver for Adobe Portable Document Format (PDF) files.

---

## 1. Pipeline Execution Flow (`PDFCDRProcessor`)

[`PDFCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pdf/PDFCDRProcessor.java) executes a multi-pass security pipeline:

1. **Hash & Input Bounds Verification**:
   - Computes initial input SHA-256 (`CDRFileUtil.sha256(inputFile)`).
   - Validates file size against `PDFSecurityPolicy.MAX_INPUT_BYTES` (200 MB).
2. **Document Load & Page Limit Check**:
   - Ingests the PDF object graph into Apache PDFBox [`PDDocument`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pdf/PDFCDRProcessor.java) via `Loader.loadPDF(inputFile.toFile())`.
   - Asserts page count > 0 and <= `PDFSecurityPolicy.MAX_PAGES` (10,000 pages).
3. **Multi-Pass Threat Analysis**:
   - Executes [`PDFThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFThreatAnalyzer.java) across catalog, name trees, page trees, actions, annotations, and AcroForms.
   - Executes [`PDFEmbeddedPayloadInspector`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFEmbeddedPayloadInspector.java) to inspect the raw byte streams of all embedded file attachments for native executables, scripts, or archive payloads.
4. **Clean Copy Check**:
   - If no blocking findings (`THREAT`, `POLICY_VIOLATION`, `SUSPICIOUS`) exist:
     - Copies the original PDF directly to output (`CDRFileUtil.copyOriginal`).
     - Asserts byte-for-byte SHA-256 identity (`cleanCopy = true`).
     - Returns [`CDRResult`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRResult.java).
5. **Sanitization Pass**:
   - Executes [`PDFThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java) on the loaded `PDDocument`.
   - Strips JavaScript trees, embedded file trees, `OpenAction`, `AA` dictionaries, `XFA` forms, digital signatures, and active page annotations.
6. **Isolated Serialization**:
   - Clears security (`document.setAllSecurityToBeRemoved(true)`).
   - Saves document to a temporary file (`.docshield-pdf-*.tmp`) in the output parent directory.
   - Atomically renames temporary file to destination path upon successful write.
7. **Post-Reconstruction Independent Re-verification**:
   - Re-loads the generated PDF file from disk via `Loader.loadPDF(outputFile.toFile())`.
   - Runs [`PDFIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/pdf/PDFIntegrityValidator.java) to force resolution of media boxes, resources, and catalog trees.
   - Runs `PDFThreatAnalyzer` on the reloaded document.
   - Runs [`PDFSecuritySurfaceVerifier`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFSecuritySurfaceVerifier.java) for low-level COS dictionary and stream inspection.
   - Asserts zero residual blocking findings.
8. **Result Assembly**: Computes output SHA-256 and returns `CDRResult`. If verification fails, the output file is deleted and the input is quarantined.
