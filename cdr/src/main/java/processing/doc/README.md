# Legacy DOC CDR Processor (`processing.doc`)

`DOCCDRProcessor` is the CDR entry point for legacy Microsoft Word `.doc` files.

## Workflow
1. Normal input validation and format identification occur in `Main`.
2. `DOCToDOCXConverter` starts LibreOffice as a separate headless subprocess.
3. LibreOffice uses a private temporary user profile and temporary conversion workspace.
4. Conversion is bounded by input-size, output-size, diagnostic-output, and process-time limits.
5. Conversion failures preserve the diagnostic reason for `Main` to print and quarantine.
6. A successful temporary DOCX is passed into the existing `DOCXCDRProcessor`.
7. The existing DOCX analyze → sanitize → reconstruct → reopen → integrity/security verification pipeline runs unchanged.
8. Only a successful CDR result is retained at the requested output path.
9. Temporary LibreOffice artifacts are removed.

The original `.doc` is never overwritten.
