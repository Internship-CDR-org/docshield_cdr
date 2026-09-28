# Legacy XLS Parsing (parsing.xls)

This package handles legacy Microsoft Excel 97–2003 (.xls) input.

## Current architecture

The live XLS parser does not maintain a second native HSSF semantic extraction pipeline. Legacy XLS processing uses the isolated LibreOffice conversion boundary and then the modern XLSX CDR pipeline.

~~~text
XLS
 │
 ▼
XLSParser
 │
 ▼
LegacyOfficeConverter
 │   └─ isolated LibreOffice subprocess
 │   └─ private temporary profile
 │   └─ timeout + output-size limits
 ▼
XLSX
 │
 ▼
XLSXParser
 │
 ▼
modern OOXML CDR pipeline
~~~

## Files

| File | Responsibility |
|---|---|
| XLSParser.java | Orchestrates XLS → XLSX conversion and parsing. |
| XLSParseResult.java | Stores conversion/parsing status and extraction statistics. |
| XLSToXLSXConverter.java | Thin XLS-specific adapter over LegacyOfficeConverter. |

## Security boundary

The original XLS is inspected by the legacy threat-analysis layer before conversion. That analysis includes OLE storage inspection and XLS-specific security indicators where applicable.

Conversion is performed out-of-process through security.sandbox.SubprocessSandbox, with timeout and output-size controls.

The former standalone HSSF content/metadata/resource/structure/hyperlink helpers were removed because the current parser no longer calls them.

## Failure behavior

If conversion fails, times out, exceeds resource limits, produces no valid XLSX, or the converted XLSX cannot be safely processed, the release path fails closed and the input is quarantined.
