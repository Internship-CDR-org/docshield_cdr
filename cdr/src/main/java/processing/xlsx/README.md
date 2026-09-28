# XLSX Processing Pipeline (`processing.xlsx`)

The `processing.xlsx` package contains the pipeline driver for Microsoft Excel workbooks.

---

## 1. Pipeline Execution Flow (`XLSXCDRProcessor`)

[`XLSXCDRProcessor`](XLSXCDRProcessor.java) executes the following sequence:

1. **Hash Input**: Computes initial SHA-256 (`CDRFileUtil.sha256(inputFile)`).
2. **Read Package**: Ingests the SpreadsheetML package into an in-memory [`OOXMLPackage`](..\..\model\ooxml\OOXMLPackage.java) via [`OOXMLPackageReader`](..\..\parsing\ooxml\OOXMLPackageReader.java).
3. **Threat Analysis**: Runs [`XLSXThreatAnalyzer`](..\..\threat\xlsx\XLSXThreatAnalyzer.java) to detect VBA macros, XLM macro sheets (`xl/macrosheets/`), ActiveX controls, DDE command formulas, external workbook links, active calculation functions (`RTD`, `CALL`, `WEBSERVICE`), external data connections (`xl/connections.xml`), and embedded payloads.
4. **Sanitization Pass**:
   - Executes [`XLSXThreatSanitizer`](..\..\sanitization\xlsx\XLSXThreatSanitizer.java).
   - Executes [`RecursiveOOXMLSanitizer`](..\..\sanitization\common\RecursiveOOXMLSanitizer.java) on embedded packages in memory.
5. **Clean Copy Check**:
   - If no blocking findings were discovered, copies input byte-for-byte to output (`CDRFileUtil.copyOriginal`) and verifies SHA-256 identity (`cleanCopy = true`).
6. **Reconstruction**:
   - If actionable threats were present, serializes the sanitized package via [`OOXMLPackageWriter`](..\..\reconstruction\OOXMLPackageWriter.java).
7. **Bounded Hardening & Verification Loop (Up to 3 Passes)**:
   - Re-reads output via `OOXMLPackageReader`.
   - Validates structural integrity via [`OOXMLIntegrityValidator`](..\..\validation\ooxml\OOXMLIntegrityValidator.java).
   - Re-analyzes with `XLSXThreatAnalyzer`.
   - Checks embedded payload safety with `RecursiveOOXMLSanitizer.hasBlockingEmbeddedContent`.
   - If clean: breaks loop.
   - If blocking findings remain and `pass < 3`: re-sanitizes, re-runs recursive sanitizer, and rewrites output to disk.
8. **Result Assembly**: Computes output SHA-256 and returns [`CDRResult`](..\common\CDRResult.java).
