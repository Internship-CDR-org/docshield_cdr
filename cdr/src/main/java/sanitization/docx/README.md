# DOCX Sanitization Subsystem (`sanitization.docx`)

The `sanitization.docx` package provides the WordprocessingML sanitization entry point for DocShield CDR.

---

## 1. Architectural Role

[`DOCXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/docx/DOCXThreatSanitizer.java) delegates package-level mutation to the shared [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java). This ensures that DOCX documents benefit from unified graph-closure sanitization, DTD stripping, and relationship disarming, while applying Word-specific field instruction disarming.

---

## 2. DOCX Finding to Action Mapping

| Finding Type | Target / Location | Sanitization Mechanism | Impact on Document |
|---|---|---|---|
| `VBA_PROJECT` | `word/vbaProject.bin`, `word/vbaData.xml` | Removes physical binary part, removes relationship from `word/_rels/document.xml.rels`, prunes `[Content_Types].xml`. | Macros disabled; visual content preserved. |
| `ACTIVEX_OBJECT` | `word/activeX/activeX*.xml`, `.bin` | Removes parts, removes incoming relationships, strips XML references. | Interactive controls removed. |
| `DDE` | `word/document.xml`, headers, footers | Reconstructs fragmented `w:instrText` buffers across runs; strips `DDE` / `DDEAUTO` field instructions while preserving cached `w:t` text runs. | Command execution blocked; displayed text preserved. |
| `EXTERNAL_RESOURCE` | `INCLUDE`, `INCLUDETEXT`, `IMPORT` fields | Strips external include field instructions; retains cached field result runs. | Remote template/file injection neutralized. |
| `EXTERNAL_TEMPLATE` | Attached template relationships | Removes attached template relationship and strips `word/settings.xml` template references. | Remote template hijacking blocked. |
| `DANGEROUS_URI` | `HYPERLINK` fields (`file:`, `javascript:`, `shell:`, `ms-app:`) | Removes dangerous `HYPERLINK` field instructions or relationship targets; benign web links (`http://`, `https://`) remain untouched. | URI execution exploits neutralized. |
| `DANGEROUS_ACTION` | `MACROBUTTON` fields | Strips `MACROBUTTON` field instructions from XML runs. | Macro invocation click triggers removed. |
| `AUTO_UPDATE_FIELDS` | `word/settings.xml` | Removes `<w:updateFields w:val="true"/>` setting. | Prevents Word from auto-evaluating fields on document open. |
| `EXTERNAL_CONNECTION` | `word/settings.xml` | Strips `<w:mailMerge>` data source blocks. | Prevents exfiltration via mail merge queries. |
| `EMBEDDED_PACKAGE` / `OLE_OBJECT` | `word/embeddings/` | Deep recursive CDR via [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) if OOXML; deletes part if unsafe or non-OOXML. | Safe embedded sheets preserved; malicious payloads removed. |
| `MALICIOUS_XML` | Any XML part | Strips `<!DOCTYPE>` and `<!ENTITY>` declarations; removes custom entity references. | Neutralizes XML External Entity (XXE) and billion laughs bombs. |

---

## 3. Workflow Inside `DOCXCDRProcessor`

1. [`DOCXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/docx/DOCXCDRProcessor.java) parses package into [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) and runs [`DOCXThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/docx/DOCXThreatAnalyzer.java).
2. If clean, byte-for-byte original copy is preserved (SHA-256 identity verified).
3. If threats exist, `DOCXThreatSanitizer.sanitize(packageData, findings)` executes in-place disarming.
4. [`RecursiveOOXMLSanitizer.sanitizeEmbeddedPackages`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) sanitizes nested packages.
5. Package is reconstructed via [`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
6. Post-reconstruction hardening loop re-reads output, runs [`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java), and re-analyzes up to 3 passes before release.
