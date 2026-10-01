# XLSX Threat Analysis (`threat.xlsx`)

## Overview

The `threat.xlsx` package provides Excel-specific security analysis layered on top of `OOXMLThreatAnalyzer` and `OLEAnalyzer`.

Excel spreadsheets possess powerful calculation and external integration capabilities that attackers abuse for execution and data exfiltration. `XLSXThreatAnalyzer` inspects Excel 4.0 (XLM) macro sheets, DDE formula pipes, external workbook link structures, active formula functions, query tables, and external data connections.

---

## Key Classes & Architecture

### [`XLSXThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/xlsx/XLSXThreatAnalyzer.java)
- **Path**: `src/main/java/threat/xlsx/XLSXThreatAnalyzer.java`
- **Delegation Flow**:
  1. Invokes [`OOXMLThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java) for common package-level checks.
  2. Invokes [`OLEAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OLEAnalyzer.java) for embedded OLE payloads.
  3. Scans worksheet `<f>` elements and `xl/workbook.xml` `<definedName>` formulas.
  4. Scans external link structures (`xl/externallinks/`), data connections (`xl/connections.xml`), and query tables (`xl/querytables/`).

---

## Threat Detection Coverage Table

| Threat / Capability | Detection Class | Evidence Checked | Classification & Severity | Blocking? | Sanitized? |
|---|---|---|---|---|---|
| **Excel 4.0 / XLM Macro Sheet** | `XLSXThreatAnalyzer` | `xl/macrosheets/`, `xl/dialogsheets/`, ContentType `...macrosheet...`, `...dialogsheet...` | `THREAT` / `CRITICAL` | **YES** | **YES** (macro-sheet part + relationships removed) |
| **DDE Formula Pipe** | `XLSXThreatAnalyzer` | DDE formula syntax (e.g. `cmd\|' /C ...'!A0` or `DDE(...)`) in `<f>` or `<definedName>` | `THREAT` / `CRITICAL` | **YES** | **YES** (formula instruction stripped; cached `<v>` value cleared) |
| **DDE / OLE External Link Structure** | `XLSXThreatAnalyzer` | `ddelink`, `olelink`, `EXEC`, `CALL`, `RUN` inside `xl/externallinks/` XML | `THREAT` / `CRITICAL` | **YES** | **YES** (external-link part + relationships removed) |
| **External Workbook Link / Formula** | `XLSXThreatAnalyzer` | Formula syntax referencing `[Workbook.xlsx]Sheet!A1` or `xl/externallinks/` part | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (formula instruction stripped; cached value preserved) |
| **Active Formula Function (Code/Macro)** | `XLSXThreatAnalyzer` | `RTD(`, `CALL(`, `REGISTER.ID(`, `EXEC(`, `RUN(`, `GET.CELL(`, `GET.WORKBOOK(` | `THREAT` / `CRITICAL` | **YES** | **YES** (formula instruction stripped; cached value preserved) |
| **Active Formula Function (Web/Data)** | `XLSXThreatAnalyzer` | `WEBSERVICE(`, `FILTERXML(` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (formula instruction stripped; cached value preserved) |
| **Dangerous HYPERLINK Formula** | `XLSXThreatAnalyzer` | `HYPERLINK("file:...")`, `javascript:`, `vbscript:`, `data:`, `ms-`, `shell:`, `mk:`, `\\` UNC | `THREAT` / `HIGH` | **YES** | **YES** (formula instruction stripped; cached text preserved) |
| **External Data Connection (High-Risk)** | `XLSXThreatAnalyzer` | `webPr`, `dbPr`, `textPr`, `olapPr`, `odbc`, `oledb`, `connectionString`, `server=` in `xl/connections.xml` | `THREAT` / `CRITICAL` | **YES** | **YES** (connections part + relationship removed) |
| **External Data Connection (Standard)** | `XLSXThreatAnalyzer` | Standard connection configuration in `xl/connections.xml` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (connections part + relationship removed) |
| **Query Table / External Refresh** | `XLSXThreatAnalyzer` | `xl/querytables/`, `xl/queries/`, relationship type `.../queryTable` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (query table part + relationship removed) |
| **Dangerous External Relationship URI** | `XLSXThreatAnalyzer` | External relationship targeting `file:`, `javascript:`, `vbscript:`, `data:`, `ms-`, `shell:` | `THREAT` / `CRITICAL` | **YES** | **YES** (relationship removed) |
| **Ordinary Formula / Hyperlink** | `XLSXThreatAnalyzer` | Standard calculation formulas (e.g. `SUM(A1:A10)`) and web hyperlinks | `OBSERVATION` / `INFO` | **NO** | **Preserved unchanged** |
