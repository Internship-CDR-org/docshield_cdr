# XLSX Security Pass 1

This pass adds Excel-specific capability detection on top of the common OOXML security analyzer.

Covered surfaces include VBA/ActiveX/OLE through the common layer, XLM macro sheets, external workbook-link parts and formulas, external data connections, query/query-table structures, DDE-style formulas, RTD/CALL/REGISTER.ID/EXEC/RUN/GET.CELL/GET.WORKBOOK active formulas, dangerous HYPERLINK formula URIs, and recursive embedded OOXML through the existing common CDR engine.

Sanitization is policy-driven: dedicated external-link/connection/XLM parts are removed; dangerous or active worksheet formulas are removed while cached values are preserved where possible; ordinary HTTPS hyperlinks and ordinary formulas remain preserved.
