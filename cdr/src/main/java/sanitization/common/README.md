# Common OOXML Sanitization (`sanitization.common`)

The `sanitization.common` package implements the core mutation and disarming logic for all Open Packaging Conventions (OPC / OOXML) formats (`DOCX`, `PPTX`, `XLSX`).

---

## 1. Architectural Role

OPC documents are ZIP packages containing XML parts, binary media, and relationship graphs (`.rels`). Rather than reinventing format-specific parsers and sanitizers for every XML element, DocShield uses [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java) as a unified mutation boundary.

When an analyzer identifies a threat:
1. The threat finding specifies the affected part, relationship ID, or XML construct.
2. The sanitizer executes surgical removals and XML modifications on the in-memory [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java).
3. The package graph is cleaned up to prevent orphaned content types, broken relationship IDs, or dangling XML references.

---

## 2. Core Classes

### `Sanitizer<T>`
Common interface defining:
```java
List<String> sanitize(T document, List<SecurityFinding> findings);
```

### `OOXMLThreatSanitizer`
The primary mutation engine implementing `Sanitizer<OOXMLPackage>`. Key capabilities include:

#### A. Relationship and Part Severance
- **`removeRelationship(pkg, finding, actions)`**: Removes the relationship from the source part's `.rels` file and strips all XML element references (`r:id`, `r:embed`, `r:link`) targeting that relationship ID.
- **`removeUnsafePart(pkg, partName, actions, removedParts)`**:
  - Finds and removes all incoming relationships targeting the unsafe part across the entire package.
  - Cleans up XML elements referencing those incoming relationship IDs.
  - Removes all outgoing relationships defined by the unsafe part.
  - Removes the physical [`OOXMLPart`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPart.java) data.
  - Strips the part's `<Override>` declaration from `[Content_Types].xml`.

#### B. XML-Level Sanitization
- **XML Declarations (`MALICIOUS_XML`)**: Removes unsafe `<!DOCTYPE ...>` blocks and `<!ENTITY ...>` declarations from XML parts via `sanitizeXmlDeclarations`. Custom entity references defined in stripped DTDs are pruned to avoid unresolved reference errors while preserving the five standard XML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`).
- **Word Field Instructions (`DDE`, `EXTERNAL_RESOURCE`, `DANGEROUS_URI`, `DANGEROUS_ACTION`)**: Word fields can be split across multiple `w:instrText` and `w:fldChar` tags (e.g., `begin`, `separate`, `end`). `stripWordFieldInstructions` reconstructs the fragmented instruction buffer across runs, removes only the dangerous instruction elements (`DDE`, `DDEAUTO`, `INCLUDE`, `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, `IMPORT`, `MACROBUTTON`, or unsafe `HYPERLINK`), and preserves the cached displayed text (`w:t`) inside the result region.
- **PowerPoint Actions (`DANGEROUS_ACTION`)**: `removeDangerousPptxActions` matches `<a:hlinkClick>` and `<a:hlinkHover>` elements carrying `ppaction://` schemes (`program`, `macro`, `ole`, `hlinkfile`, `hlinkpres`) or `action="runprogram|runmacro|oleverb"`, removes their associated relationships, and deletes the action elements and attributes.
- **Excel Formulas (`DDE`, `EXTERNAL_WORKBOOK`, `ACTIVE_FORMULA`)**:
  - `removeExcelDdeFormulaElements`: Clears both the `<f>` formula and cached `<v>` result values from cells referencing external DDE command pipelines (e.g., `cmd|/C ...`).
  - `removeExcelExternalFormulaElements`: Strips `<f>` formula elements referencing external workbooks (e.g., `[Book2.xlsx]Sheet1!A1`) while preserving the cached display value `<v>`.
  - `removeExcelActiveFormulaElements`: Strips active execution functions (`RTD`, `CALL`, `REGISTER.ID`, `EXEC`, `RUN`, `GET.CELL`, `GET.WORKBOOK`, `WEBSERVICE`, `FILTERXML`) and dangerous `HYPERLINK()` targets from worksheet formulas and workbook-level `<definedName>` formulas.
- **Word Settings (`AUTO_UPDATE_FIELDS`, `EXTERNAL_CONNECTION`)**: Strips `<w:updateFields w:val="true"/>` and `<w:mailMerge>` blocks from `word/settings.xml`.

#### C. Graph-Closure Cleanup
- **`cleanupDanglingRelationshipReferences`**: Performs a final sweep across all XML parts, stripping any remaining `r:id`, `r:embed`, or `r:link` attributes whose IDs no longer exist in the part's `.rels` relationship table.
- **`cleanupOrphanedContentTypes`**: Removes `[Content_Types].xml` entries for all deleted parts.

---

## 3. Recursive OOXML Sanitization (`RecursiveOOXMLSanitizer`)

Embedded packages (e.g., an Excel sheet embedded inside a Word document under `word/embeddings/oleObject1.bin` or `embedded.docx`) represent nested attack surfaces. DocShield does not treat embedded objects as opaque binary blobs.

### Workflow
1. Scans all candidate embedded parts (`/embeddings/`, `/media/`, `.bin`, `.docx`, `.xlsx`, `.pptx`).
2. Identifies if the embedded payload is a ZIP/OOXML package or an OLE storage containing nested OOXML streams.
3. Unpacks the nested package in-memory using [`OOXMLPackageReader`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ooxml/OOXMLPackageReader.java).
4. Runs full threat analysis ([`OOXMLThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java) + format analyzer) and sanitizes via [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java).
5. Reconstructs the nested package in memory via [`OOXMLPackageWriter.writeToBytes`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
6. If clean, updates the containing part's byte array with the reconstructed data.
7. If the nested package cannot be safely parsed, exceeds limits, or retains blocking threats after sanitization, the containing embedded part is removed completely from the parent package.

### Resource Limits (Fail-Closed)
| Parameter | Constant | Default Limit | Purpose |
|---|---|---|---|
| Max Recursion Depth | `DEFAULT_MAX_DEPTH` | `4` | Prevents deeply nested package zip-bombs |
| Max Embedded Size | `DEFAULT_MAX_EMBEDDED_BYTES` | `64 MB` (`67,108,864` bytes) | Restricts nested archive memory allocation |
| Max Nested ZIP Entries | `DEFAULT_MAX_ZIP_ENTRIES` | `10,000` | Guards against ZIP entry inflation attacks |
| Max Embedded Packages | `DEFAULT_MAX_EMBEDDED_PACKAGES` | `256` | Bounds total nested package count per document |

> **Security Guarantee**: If any limit is exceeded, or if an embedded format cannot be safely identified, `hasBlockingEmbeddedContent` returns `true`, blocking release and triggering quarantine.
