# XLSX Security Surface Inventory

This inventory records the Excel-specific capabilities currently handled by DocShield. It is a security coverage checklist, not a claim that every future Excel feature or unknown vulnerability is automatically covered.

| Surface | Detector | Default CDR action | Preservation behavior |
|---|---|---|---|
| VBA project | package part/content type + relationship | Remove | Workbook structure preserved; macro project removed |
| VBA signature/data | package part/content type | Remove | Other workbook parts preserved |
| ActiveX/control | package path/content type + relationship | Remove | Unrelated sheets/cells preserved |
| OLE | embedded part/relationship + common payload analysis | Preserve if safe; remove if unsafe | Safe OLE is not deleted merely because it exists |
| Native executable/script embedding | payload signature/name | Remove | Containing unsafe embedded boundary removed |
| XLM macro/dialog sheet | macrosheet/dialogsheet path/content type | Remove | Other sheets preserved |
| External workbook link part | `xl/externalLinks/*` + relationship | Remove | Ordinary hyperlinks preserved |
| External workbook formula | `[book.xlsx]Sheet!A1`-style formula reference | Remove formula; preserve cached value where possible | Cell remains with cached value |
| External defined-name formula | external workbook reference in workbook XML | Remove external reference/instruction | Non-active workbook content preserved where possible |
| DDE/DDEAUTO | worksheet/external-link formula/link structure | Remove active instruction/boundary | Cached value preserved where possible |
| External data connection | `xl/connections.xml`, connection relationship/content | Remove | Workbook remains without external refresh configuration |
| Query table/query structure | query-table/query part path/content/relationship | Remove | Workbook remains without external query configuration |
| RTD | formula-function inspection | Remove formula; preserve cached value | Cell value remains where present |
| CALL / REGISTER.ID | formula-function inspection | Remove formula | Cached value preserved where possible |
| EXEC / RUN / GET.CELL / GET.WORKBOOK | active/XLM formula inspection | Remove active formula/macro boundary | Safe workbook content preserved |
| WEBSERVICE | formula-function inspection | Remove formula | Cached value preserved where possible |
| FILTERXML | active/external-data formula inspection | Remove formula under current policy | Cached value preserved where possible |
| Dangerous HYPERLINK URI | formula URI inspection | Remove formula | Display/cached value preserved where present |
| Dangerous external relationship URI | relationship target scheme | Remove relationship/reference | Ordinary HTTPS hyperlink preserved |
| Normal HTTPS hyperlink | relationship analysis | Preserve | User-facing link remains |
| Malicious XML / DTD / ENTITY | common XML security layer | Reject/sanitize | Safe package content preserved only when structurally safe |
| Invalid relationship | common relationship graph validation | Remove invalid reference/relationship | Unrelated package graph preserved |
| Path traversal | package reader/common analyzer | Reject | Untrusted package not reconstructed |
| Nested OOXML | recursive format-aware CDR | Recursively sanitize and reconstruct | Safe embedded document preserved |
| Uninspectable nested package | recursive security budget | Fail closed / remove boundary | Never silently trusted |

## Hardening status

The XLSX hardening pass adds regression coverage for formula-level active content, defined-name formulas, relationship graph cleanup, external-link/connection cleanup, XLM, ActiveX, OLE preservation, and reconstructed-package integrity.
