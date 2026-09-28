# PPTX Sanitization Subsystem (`sanitization.pptx`)

The `sanitization.pptx` package provides the PresentationML sanitization entry point for DocShield CDR.

---

## 1. Architectural Role

[`PPTXThreatSanitizer`](PPTXThreatSanitizer.java) delegates package mutations directly to [`OOXMLThreatSanitizer`](..\common\OOXMLThreatSanitizer.java). This handles PresentationML-specific active features (such as click/hover actions, active control properties, and embedded payloads) within the shared OOXML graph disarming engine.

---

## 2. PPTX Finding to Action Mapping

| Finding Type | Target / Location | Sanitization Mechanism | Impact on Presentation |
|---|---|---|---|
| `VBA_PROJECT` | `ppt/vbaProject.bin`, `ppt/vbaData.xml` | Removes physical binary parts, incoming relationships from presentation/slide `.rels`, and `[Content_Types].xml` entries. | Macros disabled; slide visuals preserved. |
| `ACTIVEX_OBJECT` | `ppt/activeX/activeX*.xml`, `ppt/controlProps/ctrlProp*.xml` | Removes control parts, strips incoming relationships, and deletes XML `<p:control>` or shape tags. | Active controls neutralized. |
| `DANGEROUS_ACTION` | `<a:hlinkClick>`, `<a:hlinkHover>` carrying `ppaction://` | Removes associated action relationship from slide `.rels`; deletes `<a:hlinkClick>` / `<a:hlinkHover>` elements and strips `action` / `actionType` attributes. | Disarms program launches, macro triggers, and OLE verb actions on click/hover. |
| `OLE_OBJECT` / `EMBEDDED_PACKAGE` | `ppt/embeddings/` (`.bin`, `.ole`, `.docx`, `.xlsx`) | If nested OOXML: recursively sanitized via [`RecursiveOOXMLSanitizer`](..\common\RecursiveOOXMLSanitizer.java); if raw binary executable (`PE`, `ELF`, `Mach-O`, scripts, EICAR) or malformed: removed entirely along with slide relationship. | Neutralizes dropped executable exploits. |
| `SUSPICIOUS_SVG` | `ppt/media/*.svg` | Strips SVG parts containing `<script>` or event handlers (`onload`, `onclick`); removes `<a:blip r:embed="..."/>` references. | SVG script execution blocked. |
| `DANGEROUS_URI` | Slide relationships targeting `file:`, `javascript:`, `data:`, `shell:` | Severed from slide `.rels` files; XML relationship references stripped. | External URI protocol hijacking prevented. |
| `MALICIOUS_XML` | Slide XML, presentation XML | Strips DTD `<!DOCTYPE>` and entity declarations. | XXE and expansion attacks neutralized. |

---

## 3. Workflow Inside `PPTXCDRProcessor`

1. [`PPTXCDRProcessor`](..\..\processing\pptx\PPTXCDRProcessor.java) parses package into [`OOXMLPackage`](..\..\model\ooxml\OOXMLPackage.java) and runs [`PPTXThreatAnalyzer`](..\..\threat\pptx\PPTXThreatAnalyzer.java).
2. If clean, byte-for-byte original copy is preserved (SHA-256 identity verified).
3. If threats exist, `PPTXThreatSanitizer.sanitize(packageData, findings)` disarms active elements.
4. [`RecursiveOOXMLSanitizer`](..\common\RecursiveOOXMLSanitizer.java) sanitizes nested packages in-memory.
5. Package is reconstructed via [`OOXMLPackageWriter`](..\..\reconstruction\OOXMLPackageWriter.java).
6. Post-reconstruction loop re-reads output, verifies integrity via [`OOXMLIntegrityValidator`](..\..\validation\ooxml\OOXMLIntegrityValidator.java), and checks for residual threats across up to 3 passes before release.
