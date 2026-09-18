# PPTX Processing Pipeline (`processing.pptx`)

The `processing.pptx` package contains the pipeline driver for Microsoft PowerPoint presentations.

---

## 1. Pipeline Execution Flow (`PPTXCDRProcessor`)

[`PPTXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pptx/PPTXCDRProcessor.java) executes the following sequence:

1. **Hash Input**: Computes initial SHA-256 (`CDRFileUtil.sha256(inputFile)`).
2. **Read Package**: Ingests the PresentationML package into an in-memory [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) via [`OOXMLPackageReader`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ooxml/OOXMLPackageReader.java).
3. **Threat Analysis**: Runs [`PPTXThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/PPTXThreatAnalyzer.java) to detect VBA macros, ActiveX, control properties, click/hover actions (`ppaction://`), malicious SVGs, OLE/native payloads, and dangerous relationships.
4. **Sanitization Pass**:
   - Executes [`PPTXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pptx/PPTXThreatSanitizer.java).
   - Executes [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) on embedded packages in memory.
5. **Clean Copy Check**:
   - If no blocking findings were discovered, copies input byte-for-byte to output (`CDRFileUtil.copyOriginal`) and verifies SHA-256 identity (`cleanCopy = true`).
6. **Reconstruction**:
   - If actionable threats were present, serializes the sanitized package via [`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
7. **Bounded Hardening & Verification Loop (Up to 3 Passes)**:
   - Re-reads output via `OOXMLPackageReader`.
   - Validates structural integrity via [`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java).
   - Re-analyzes with `PPTXThreatAnalyzer`.
   - Checks embedded payload safety with `RecursiveOOXMLSanitizer.hasBlockingEmbeddedContent`.
   - If clean: breaks loop.
   - If blocking findings remain and `pass < 3`: re-sanitizes, re-runs recursive sanitizer, and rewrites output to disk.
8. **Result Assembly**: Computes output SHA-256 and returns [`CDRResult`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRResult.java).
