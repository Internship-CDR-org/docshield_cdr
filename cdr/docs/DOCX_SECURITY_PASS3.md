# DOCX Security Pass 3 — Final Hardening

This pass closes the DOCX trust-boundary gap before XLSX work begins.

## Changes

- DOCX processing now invokes `RecursiveOOXMLSanitizer` for embedded OOXML packages.
- Recursive inspection is format-aware: nested DOCX, XLSX and PPTX packages use their format-specific analyzers.
- Nested packages are sanitized, reconstructed in memory, and re-analyzed before being preserved.
- If nested content cannot be safely inspected, exceeds configured security limits, or remains blocking after sanitization, its containing embedded package is removed.
- Post-reconstruction DOCX processing verifies both the outer package findings and recursively embedded content.

## Security decision model

| Condition | Decision |
|---|---|
| Embedded OOXML is clean | Preserve and reconstruct |
| Embedded OOXML has removable threat and becomes clean | Sanitize nested package and preserve it |
| Nested package remains unsafe | Remove containing embedded package |
| Nested package cannot be parsed/reconstructed | Remove containing embedded package |
| Resource/depth/package limit reached | Fail closed; remove containing embedded package |

## Important preservation rule

An embedded object is not removed merely because it is OLE/embedded. Its contents must be shown to be unsafe, or the object must be uninspectable under the security budget.

## Pre-XLSX baseline

DOCX now uses the same outer-package and recursive OOXML trust-boundary model as PPTX. XLSX-specific work can therefore reuse the common package reader/writer, relationship cleanup, threat model, sanitizer policy and recursive CDR machinery.
