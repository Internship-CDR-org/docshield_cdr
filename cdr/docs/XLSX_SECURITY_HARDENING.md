# XLSX Security Hardening

## Scope

This pass hardens the Excel-specific OOXML security layer without treating every embedded object or formula as malicious.

## Formula safety

- Formula detection is performed per `<f>` element rather than scanning the whole worksheet XML for function names.
- Active functions covered by the current policy: `RTD`, `CALL`, `REGISTER.ID`, `EXEC`, `RUN`, `GET.CELL`, `GET.WORKBOOK`, `WEBSERVICE`, and `FILTERXML`.
- Dangerous `HYPERLINK` URI targets are detected separately.
- DDE/DDEAUTO and external-workbook references are detected inside formulas.
- Excel `definedName` formulas in `xl/workbook.xml` are also inspected because they are not represented by worksheet `<f>` elements.
- Sanitization removes the formula instruction while retaining the containing cell and cached `<v>` value when present.
- Ordinary formulas such as `SUM(1,2)` and ordinary HTTPS HYPERLINK formulas are preserved.

## Package graph safety

- Relationship references (`r:id`, `r:embed`, `r:link`) are now validated by the common OOXML analyzer for DOCX, XLSX and PPTX rather than only PPTX.
- Dangling references are removed before reconstruction.
- Removing an unsafe package part also removes incoming relationships, outgoing relationships originating from that part, and the part's explicit content-type declaration.

## Active/external Excel structures

- VBA projects
- ActiveX/control relationships and parts
- XLM macro/dialog sheets
- external workbook link parts/relationships
- external data connections
- query-table/query structures
- executable embedded payloads
- dangerous external URI relationships

## Preservation policy

A finding classified only as `OBSERVATION` does not authorize deletion. In particular, a safe/merely observed OLE object is preserved.

External workbook links, external connections, query configurations and active formula capabilities are currently treated as blocking/policy content and removed because Excel can resolve or refresh them outside the package.

## Regression coverage

`XLSXHardeningRegressionTest` covers:

- all active formula functions in the current policy
- defined-name active formulas
- normal formula preservation
- normal HTTPS HYPERLINK preservation
- XLM removal and incoming relationship cleanup
- external-link part/relationship/content-type cleanup
- connection part and outgoing relationship cleanup
- ActiveX part/relationship removal
- safe OLE observation preservation
- dangling relationship removal
- sanitized XLSX reconstruction and re-read integrity

## DDE command-pipe hardening

Legacy Excel DDE does not always contain the literal `DDE` token after binary-to-OOXML conversion. Command/data-source formulas such as `cmd|...!A0` are therefore recognized explicitly as DDE-style execution constructs.

For Excel DDE formulas, sanitization removes the formula instruction **and clears the containing cell's cached `<v>` value**. The cached result is not treated as trusted display content because it can contain attacker-controlled payload text, including EICAR test content.

DDE findings attached to `xl/externalLinks/` parts remove the complete external-link package part, incoming relationships, outgoing relationships and the corresponding content-type declaration rather than merely rewriting the XML in place.
