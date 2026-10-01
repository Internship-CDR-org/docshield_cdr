# Legacy XLS Processing Pipeline (`processing.xls`)

The `processing.xls` package contains the Content Disarm and Reconstruction driver for legacy Microsoft Excel binary workbooks (`.xls` - Excel 97-2003 BIFF8 / Compound File Binary Format).

---

## 1. Architectural Philosophy: Pre-Conversion Analysis + Sandboxed CDR

Legacy Excel binary workbooks (`.xls`) represent one of the most weaponized enterprise document formats. They can host VBA macros, XLM (Excel 4.0) macro sheets, binary DDE links, external workbook references, and malicious formula records (`cmd|' /C ...'!A1`).

To prevent silent sanitization bypasses during conversion, DocShield executes a strict pipeline:

```
Legacy .xls Input
       │
       ▼ 1. Pre-Conversion Inspection (XLSThreatAnalyzer)
       │    • Scan OLE2 streams (Workbook, Book) for VBA project storages
       │    • Inspect BIFF8 records for XLM macro sheets and DDE formula pipes
       │    • Detect Ole10Native embedded executables
       │
       ▼ 2. Sandboxed LibreOffice Conversion (XLSToXLSXConverter)
       │    • Runs in SubprocessSandbox with memory and timeout enforcement
       │    • Converts BIFF8 binary workbook to modern SpreadsheetML XLSX
       │
       ▼ 3. Modern XLSX CDR (XLSXCDRProcessor)
       │    • Full threat analysis, DDE disarming, external link stripping, and reconstruction
       │    • Post-reconstruction integrity verification
       │
       ▼ 4. Findings & Action Aggregation
       │    • Merges pre-conversion legacy findings with modern disarming actions
       │
       ▼ 5. Workspace Cleanup & Release
            • Securely deletes temporary conversion workspace
            • Emits clean, verified modern XLSX artifact
```

---

## 2. Core Implementation: `XLSCDRProcessor`

- [`XLSCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/xls/XLSCDRProcessor.java) implements [`CDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRProcessor.java).
- Executes pre-conversion threat analysis via [`XLSThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/xls/XLSThreatAnalyzer.java).
- Converts binary XLS to XLSX via [`XLSToXLSXConverter.convert`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/xls/XLSToXLSXConverter.java) and [`LegacyOfficeConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/legacy/LegacyOfficeConverter.java).
- Passes the converted XLSX into [`XLSXCDRProcessor.process(converted, output, false)`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/xlsx/XLSXCDRProcessor.java).
- Cleans up temporary conversion directories in a `finally` block.
- Produces a fully disarmed modern `.xlsx` spreadsheet.
