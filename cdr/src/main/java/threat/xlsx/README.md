# XLSX Threat Analysis Subsystem (`threat.xlsx`)

The XLSX analyzer is the Excel-specific layer on top of the common OOXML security analyzer. It identifies active and external-data capabilities by structure rather than antivirus signature names.

## Covered surfaces
- VBA projects and companion data (common OOXML layer)
- ActiveX/control parts (common OOXML layer)
- OLE/embedded objects (common layer; safe objects remain observations)
- Embedded executable/native payloads (common layer)
- Excel 4.0/XLM macro sheets and dialog sheets
- External workbook-link parts and external workbook formulas/defined names
- External data connections, web/DB/OLE-DB style connection metadata
- Query tables/query structures
- DDE-style worksheet formulas and DDE/OLE external-link structures
- Active formula capabilities such as RTD, CALL, REGISTER.ID, EXEC, RUN, GET.CELL and GET.WORKBOOK
- External-data formula functions such as WEBSERVICE
- Dangerous HYPERLINK formula URIs
- Dangerous external relationship URI schemes
- Recursive embedded OOXML through the common recursive CDR engine

## Preservation policy
Ordinary formulas and ordinary HTTPS hyperlinks are preserved. Dedicated active/external-data package parts are removed. Dangerous/active formulas are disarmed by removing the formula instruction while retaining the cached cell value when the OOXML structure permits it. Safe embedded objects are not removed merely because they are embedded.
