# Legacy PPT Parsing (parsing.ppt)

This package handles legacy Microsoft PowerPoint 97–2003 (.ppt) input.

## Current architecture

The live PPT parser is intentionally small. It does not use the old in-process HSLF semantic parser helpers. The legacy binary is converted through the shared isolated LibreOffice boundary and then handled by the modern PPTX pipeline.

~~~text
PPT
 │
 ▼
PPTParser
 │
 ▼
LegacyOfficeConverter
 │   └─ isolated LibreOffice subprocess
 │   └─ private temporary profile
 │   └─ timeout + output-size limits
 ▼
PPTX
 │
 ▼
PPTXParser
 │
 ▼
modern OOXML CDR pipeline
~~~

## Files

| File | Responsibility |
|---|---|
| PPTParser.java | Orchestrates PPT → PPTX conversion and parsing. |
| PPTParseResult.java | Stores conversion/parsing status and extraction statistics. |
| PPTToPPTXConverter.java | Thin PPT-specific adapter over LegacyOfficeConverter. |

## Security boundary

The original legacy PPT is analyzed by the legacy threat-analysis layer before conversion. Conversion itself is performed out-of-process through security.sandbox.SubprocessSandbox.

The old standalone HSLF hyperlink/structure helper classes are not part of the current processing path and have been removed to avoid maintaining dead duplicate parsing logic.

## Failure behavior

Conversion or post-conversion PPTX parsing failures fail closed. The main application deletes any partial output and quarantines the input.
