# DocShield CDR Threat Matrix

This matrix is capability-oriented. It deliberately does not encode VirusTotal/vendor malware labels or individual malware-family names.

## Common OOXML layer (DOCX / PPTX / XLSX)

| Capability | Detection | Common sanitizer | Current state |
|---|---|---|---|
| VBA project | package part/content type | remove part + refs + content type | Implemented |
| ActiveX/control | part path/content type | remove part + refs | Implemented |
| OLE/embedded object | embeddings path/content type | remove object + refs | Implemented |
| Native executable in embedded part | extension + PE/ELF signature | remove part + refs | Implemented |
| Dangerous external URI | relationship target | remove relationship + XML r:id/r:embed/r:link | Implemented |
| External template | relationship type + external target | remove relationship + XML reference | Implemented |
| External non-hyperlink resource | external relationship | remove relationship + XML reference | Implemented |
| External data/query connection | relationship/part naming | remove relationship/part | Implemented |
| DDE/DDEAUTO | Word field / XLSX DDE-style formula heuristic | targeted XML disarm | Implemented (first pass; more syntax coverage required) |
| XLM macro sheet | xl/macrosheets + content type | remove part + refs | Implemented (structural coverage) |
| Active SVG | script/event/javascript/vbscript/foreignObject + external URI | remove resource + relationship refs | PPTX implemented (first pass) |
| DOCTYPE / ENTITY | raw XML package scan | strip unsafe declaration/custom entity refs | Implemented (first pass) |
| Path traversal | ZIP entry path | reject input | Implemented |
| Duplicate ZIP entries | ZIP reader | reject input | Implemented |
| Uncompressed package explosion | bounded ZIP reader | reject input | Implemented |

## PPTX status after the first focused pass

- PPTX-specific `ppt/ctrlProps/` control-persistence detection is now connected to the production PPTX processor.
- PowerPoint `ppaction://program`, `ppaction://macro`, and `ppaction://ole` action constructs are detected and disarmed by the common sanitizer.
- External non-hyperlink PPTX relationships are removed; ordinary external hyperlinks remain preserved.
- Active/external SVG resources are removed with their package relationships.
- Real supplied PPTX samples were reconstructed and passed package-integrity validation.

## Still required for a high-confidence OOXML pass

- complete relationship-type catalogue for each OOXML application
- DOCX field/action coverage beyond DDE
- XLSX external links, connection/query-table semantics and XLM variants
- PPTX action/hyperlink/media semantics and SVG passive reconstruction
- recursive inspection of embedded OOXML/OLE documents rather than only the outer package
- XML reference cleanup for every relationship-bearing element type
- package/content-type graph completeness checks
- regression tests using real benign and real security-test samples

## Policy principle

A vendor label such as `EICAR`, `Trojan`, `Loader`, or a CVE name is evidence from an external scanner, not a DocShield threat category. DocShield should classify the underlying capability and sanitize that capability regardless of the vendor's label.

## PPTX Pass 2 additions

| Capability | Detection | Sanitization | Status |
|---|---|---|---|
| VBA relationship | Relationship type | Remove relationship + VBA part when present | Implemented |
| ActiveX/control relationship | Relationship type | Remove relationship + control parts | Implemented |
| OLE presence | OLE content type/signature | Observation only | Implemented |
| OLE VBA stream | OLE stream structure | Remove containing OLE object | Implemented |
| `ppaction://program` | PresentationML action | Remove action + referenced relationship | Implemented |
| `ppaction://macro` | PresentationML action | Remove action + referenced relationship | Implemented |
| `ppaction://ole` | PresentationML action | Remove action + referenced relationship | Implemented |
| `ppaction://hlinkfile` | PresentationML action | Remove external-file action + relationship | Implemented |
| `ppaction://hlinkpres` | PresentationML action | Remove external-presentation action + relationship | Implemented |

## PPTX Pass 3 additions

- Recursive embedded OOXML package discovery
- Blocking nested OOXML threat propagation to the containing PPTX embedded part
- Nested package depth and size limits
- Opaque embedded-package removal when nested content cannot be safely inspected

## Recursive embedded-content policy

Embedded OOXML packages are recursively sanitized when they can be safely parsed and reconstructed. A nested threat is not automatically grounds for deleting the useful embedded object: the nested package is sanitized first. The containing object is removed only if the nested package remains unsafe, cannot be safely processed, or crosses a configured resource boundary. OLE containers remain a conservative boundary because arbitrary OLE in-place rewriting is not yet implemented.

## DOCX Pass 2 Word-specific coverage

| DOCX surface | Detection | Sanitization / disposition |
|---|---|---|
| Fragmented DDE/DDEAUTO field | Joins `w:instrText` fragments and `w:fldSimple` instructions | Removes field instruction; preserves cached result |
| INCLUDE / INCLUDETEXT | Word field instruction analysis | Removes instruction; preserves cached result |
| INCLUDEPICTURE | Word field instruction analysis, including fragmented runs | Removes instruction; preserves cached result |
| LINK / IMPORT | Word field instruction analysis | Removes instruction; preserves cached result |
| External attached template | `attachedTemplate` relationship with external target | Removes relationship/reference |
| Macro-enabled internal attached template | Attached-template target content type / `.dotm` | Removes relationship and unsafe template part |
| Mail-merge source | `mailMergeSource` relationship | Removes external data-source relationship |
| Mail-merge recipient data | `recipientData` relationship | Removes recipient-data relationship/configuration |
| Automatic field updates | `w:updateFields w:val="true"` | Removes setting |
| External altChunk | `aFChunk` external relationship | Removes relationship |
| Active internal altChunk | HTML/XHTML script/object/embed/iframe/form or macro-enabled content type | Removes imported-content part and relationship |


## XLSX capability coverage (current pass)

| Surface | Detection | Default action |
|---|---|---|
| VBA / VBA companion parts | part name, content type, relationship | Remove |
| ActiveX / controls | part path/content type/relationship | Remove |
| OLE / embedded object | package part + relationship | Preserve as observation unless unsafe payload is confirmed |
| XLM / macro sheet | `xl/macrosheets`, `xl/dialogsheets`, macro-sheet content type | Remove |
| External workbook link part | `xl/externalLinks/*`, relationship type | Remove |
| External workbook formula / defined name | formula XML containing `[workbook]...!` | Remove formula, preserve cached value |
| External data connection | `xl/connections.xml`, connection relationship/content | Remove |
| Query/query-table structure | `xl/queryTables/*`, `xl/queries/*`, query content type | Remove |
| DDE/DDEAUTO formula/link | DDE syntax in worksheet/external-link XML | Remove active formula/link |
| RTD/CALL/REGISTER.ID/EXEC/RUN/GET.CELL/GET.WORKBOOK | formula-function analysis | Remove formula, preserve cached value |
| WEBSERVICE / external-data formula | formula-function analysis | Remove formula, preserve cached value |
| Dangerous HYPERLINK URI | formula URI analysis | Remove formula, preserve cached value |
| Normal HTTPS hyperlink | relationship analysis | Preserve |
| Nested OOXML | recursive format-aware analyzer | Sanitize recursively; fail closed when uninspectable |

See `docs/OOXML_CROSS_FORMAT_REGRESSION_MATRIX.md` for the integrated PPTX/DOCX/XLSX regression evidence.


## PDF Pass 3 additions

| Capability | Detection | Disposition |
|---|---|---|
| Embedded PDF payload | PDF magic + PDFBox recursive analysis | Inspect nested active content; remove outer attachment boundary |
| Embedded DOCX/PPTX/XLSX | OOXML structure detection + native analyzer | Inspect nested active content; remove outer attachment boundary |
| Unknown embedded payload | Unsupported format or failed inspection | Fail closed; remove attachment |
| Oversized embedded payload | Decoded payload size limit | Fail closed; remove attachment |
| Embedded payload flood | Payload-count limit | Fail closed for uninspectable boundary |
