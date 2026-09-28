# PDF CDR Pass 7 — Security Boundary Hardening

This pass hardens the existing PDF CDR implementation without expanding the trusted input surface.

## Changes

- Added a maximum COS graph depth. Exceeding it creates a critical `PDF_RESOURCE_LIMIT` finding and fails closed.
- Embedded-payload inspection no longer silently stops at the payload-count limit; reaching the limit creates a critical `PDF_RESOURCE_LIMIT` finding.
- Quarantine copies are written to a temporary file and moved into place, reducing the chance of a partial quarantine artifact.
- Quarantine filenames are collision-safe.
- Quarantine records include a SHA-256 hash of the quarantined copy.
- Quarantine reasons are normalized to one line to prevent log/report injection.
- Existing PDF reconstruction and post-reconstruction threat re-analysis remain mandatory.

## Security principle

An inspection limit is never interpreted as a clean result. If DocShield cannot complete inspection within a configured safety boundary, it must fail closed and the input must not be released as a clean reconstruction.

## Testing note

The JUnit tests are included but require the project's Maven/PDFBox dependency environment for execution.
