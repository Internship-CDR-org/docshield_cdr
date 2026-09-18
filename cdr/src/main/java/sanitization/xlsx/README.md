# XLSX Sanitization Subsystem (`sanitization.xlsx`)

The `sanitization.xlsx` package provides the SpreadsheetML sanitization entry point for DocShield CDR.

---

## 1. Architectural Role

[`XLSXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/xlsx/XLSXThreatSanitizer.java) delegates package-level mutation to the shared [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java). This handles workbook-specific threat surfaces—including XLM macro sheets, DDE execution formulas, active calculation functions, external data connections, and workbook link tables—while maintaining strict OOXML structural integrity.

---

## 2. XLSX Finding to Action Mapping

| Finding Type | Target / Location | Sanitization Mechanism | Impact on Workbook |
|---|---|---|---|
| `VBA_PROJECT` | `xl/vbaProject.bin`, `xl/vbaProjectSignature.bin` | Removes physical binary parts, incoming relationships from `xl/_rels/workbook.xml.rels`, and `[Content_Types].xml` entries. | Macros disabled; cell values and formatting preserved. |
| `XLM_MACRO` | `xl/macrosheets/sheet*.xml` | Removes the macro sheet part, strips sheet reference from `xl/workbook.xml`, and removes sheet relationships. | Excel 4.0 macro execution blocked. |
| `ACTIVEX_OBJECT` | `xl/activeX/activeX*.xml`, `.bin`, `xl/ctrlProps/` | Removes control parts, incoming relationships, and sheet drawing references. | Form controls neutralized. |
| `DDE` | Worksheet cells `<c><f>cmd\|...</f><v>...</v></c>`, `xl/externalLinks/` | Strips the `<f>` formula element AND deletes the cached `<v>` result value; removes dedicated `xl/externalLinks/` parts and relationships. | Command execution pipeline broken and malicious cached strings purged. |
| `EXTERNAL_WORKBOOK` | `[Book2.xlsx]Sheet1!A1` formula references | Removes formula `<f>` referencing external workbook brackets; retains cached display value `<v>`. | Prevents data exfiltration and external link prompts. |
| `ACTIVE_FORMULA` | Formulas calling `RTD`, `CALL`, `REGISTER.ID`, `EXEC`, `RUN`, `GET.CELL`, `WEBSERVICE`, `FILTERXML` | Strips `<f>` formula elements from worksheet cells and `<definedName>` formulas from `xl/workbook.xml`; preserves static cached `<v>` results. | Blocks arbitrary code execution and out-of-band HTTP exfiltration. |
| `EXTERNAL_CONNECTION` | `xl/connections.xml`, `xl/queryTables/`, `xl/pivotTables/` | Removes dedicated connection parts, deletes workbook relationships, and strips data refresh settings. | Neutralizes external database and web queries. |
| `DANGEROUS_URI` | `HYPERLINK("file://...")` formulas and relationship links | Strips dangerous HYPERLINK formulas and severs dangerous URI relationship links; standard web links (`http://`, `https://`) are preserved. | Local file disclosure and protocol handler execution prevented. |
| `EMBEDDED_PACKAGE` / `OLE_OBJECT` | `xl/embeddings/` (`.bin`, `.ole`, `.docx`) | Deep recursive CDR via [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java); removes unsafe non-OOXML payloads. | Benign embedded tables preserved; embedded executables removed. |
| `MALICIOUS_XML` | `xl/workbook.xml`, sheet XMLs, `[Content_Types].xml` | Strips `<!DOCTYPE>` and `<!ENTITY>` blocks; removes custom entity references. | XXE attacks neutralized. |

---

## 3. Workflow Inside `XLSXCDRProcessor`

1. [`XLSXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/xlsx/XLSXCDRProcessor.java) parses package into [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) and executes [`XLSXThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/xlsx/XLSXThreatAnalyzer.java).
2. If clean, byte-for-byte original copy is preserved (SHA-256 identity verified).
3. If threats exist, `XLSXThreatSanitizer.sanitize(packageData, findings)` disarms active elements.
4. [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) sanitizes nested packages in-memory.
5. Package is reconstructed via [`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
6. Post-reconstruction loop re-reads output, verifies integrity via [`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java), and re-analyzes up to 3 passes before release.
