# Legacy DOC Parsing (parsing.doc)

This package handles legacy Microsoft Word 97–2003 (.doc) input.

## Current architecture

DocShield does not use an in-process HWPF document parser for the main DOC processing path. The legacy binary file is treated as untrusted and is sent through the shared isolated LibreOffice conversion boundary.

~~~text
DOC
 │
 ▼
DOCParser
 │
 ▼
LegacyOfficeConverter
 │   └─ isolated LibreOffice subprocess
 │   └─ private temporary profile
 │   └─ timeout + output-size limits
 │   └─ process-tree termination on failure
 ▼
DOCX
 │
 ▼
DOCXParser
 │
 ▼
modern OOXML CDR pipeline
~~~

## Files

| File | Responsibility |
|---|---|
| DOCParser.java | Orchestrates DOC → DOCX conversion and parses the converted document. |
| DOCParseResult.java | Stores conversion/parsing status and extraction statistics used by reporting. |
| DOCToDOCXConverter.java | Thin DOC-specific adapter over LegacyOfficeConverter. |

## Security boundary

The untrusted legacy document is not handed to a native Office parser inside the main JVM. Conversion occurs through security.sandbox.SubprocessSandbox, which applies process supervision, timeout handling, bounded output monitoring, and Bubblewrap isolation when available.

Before conversion, the legacy threat-analysis layer can inspect the original binary for security-relevant indicators. This preserves evidence that could disappear during conversion.

## Failure behavior

A conversion failure, timeout, output-limit violation, malformed result, or subsequent DOCX parsing failure is treated as a processing failure. The release path is fail-closed and the input is quarantined by the application gatekeeper.

See docs/ERROR_HANDLING.md for the operator-facing error catalog.
