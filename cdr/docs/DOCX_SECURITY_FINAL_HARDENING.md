# DOCX Final Hardening Pass

## Scope

This pass is the final DOCX hardening step before XLSX work. It does not claim that an unknown future Office vulnerability can be detected. It closes the currently identified DOCX security surfaces in the DocShield architecture and verifies that embedded OOXML is not trusted merely because it is nested.

## Final behavior

1. The outer DOCX is parsed as an OOXML package.
2. DOCX-specific analysis runs in addition to common OOXML analysis.
3. The common policy sanitizes blocking findings.
4. Embedded OOXML packages are recursively analyzed with the correct format-specific analyzer (DOCX/XLSX/PPTX).
5. A nested package that can be safely sanitized is reconstructed in memory and preserved.
6. A nested package that remains unsafe, cannot be parsed/reconstructed, or exceeds the configured security budget is removed as an unsafe boundary.
7. The reconstructed DOCX is read again and analyzed again. CDR success requires both outer and recursively embedded content to have no blocking findings.

## Word-specific active field hardening

- DDE/DDEAUTO fields are detected across fragmented `w:instrText` runs.
- `MACROBUTTON` fields are treated as active actions and the instruction is removed while surrounding visible content is preserved where possible.
- Dangerous URI targets inside Word `HYPERLINK` fields are detected separately from normal hyperlink relationships and their field instruction is removed.
- INCLUDE/INCLUDETEXT/INCLUDEPICTURE/LINK/IMPORT field instructions are sanitized without intentionally deleting cached result text.

## Regression decision table

| Surface | Detection | Sanitization | Preservation rule |
|---|---|---|---|
| VBA | package part + relationship | remove project and references | ordinary document content remains |
| ActiveX | part/content type + relationship | remove control and references | unrelated content remains |
| OLE | OLE structure/payload inspection | remove only when unsafe | safe OLE is preserved |
| DDE/DDEAUTO | normalized Word field instructions | remove field instruction | cached/displayed result preserved where possible |
| MACROBUTTON | normalized Word field instructions | remove field instruction | visible content preserved |
| External field | normalized Word field instructions | remove field instruction | visible/cached result preserved where possible |
| Dangerous HYPERLINK field | field URI scheme | remove field instruction | visible/cached result preserved |
| External template | relationship + target/content type | remove unsafe relationship/part | safe local template preserved |
| Mail merge | relationship/configuration | remove external workflow state | normal document content preserved |
| altChunk | relationship + target content | remove active external/imported content | safe imported content preserved |
| Nested OOXML | package signature + format-aware recursive analyzer | sanitize and reconstruct if possible | clean nested document is preserved |
| Uninspectable nested content | depth/size/count/parse limits | fail closed and remove boundary | never silently trusted |
| Package/relationship abuse | package graph validation | remove invalid structures / reject unsafe package | legitimate graph preserved |

## Important limitation

The recursive inspection limits are security budgets, not format capabilities. They can be configured. Reaching a limit means the content is uninspectable under the configured security budget; it is never treated as safe by default.
