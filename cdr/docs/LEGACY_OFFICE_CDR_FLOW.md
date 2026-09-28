# Legacy Office CDR Flow

Legacy binary Office formats use the same CDR lifecycle as the modern formats, but conversion is an explicit trust boundary.

## DOC

`DOC -> legacy threat inspection -> isolated LibreOffice -> DOCX -> DOCX CDR -> reconstruction -> integrity validation -> final re-analysis`

## PPT

`PPT -> legacy threat inspection -> isolated LibreOffice -> PPTX -> PPTX CDR -> reconstruction -> integrity validation -> final re-analysis`

## XLS

`XLS -> legacy threat inspection -> isolated LibreOffice -> XLSX -> XLSX CDR -> reconstruction -> integrity validation -> final re-analysis`

The legacy inspection occurs before conversion because LibreOffice may remove active content while converting. Without the pre-conversion inspection, the report could incorrectly say that the original file contained no threat.

## Conversion boundary

All three legacy formats use the shared `LegacyOfficeConverter` implementation. LibreOffice runs as a separate headless OS process with a private temporary profile, a temporary output workspace, input/output size limits, bounded diagnostics, a timeout, and process-tree termination on failure.

The converted file is retained only for the duration of the CDR operation. On success the legacy processor passes it to the existing modern-format CDR processor. On conversion failure the exception contains the source format, exit/timeout condition, and available LibreOffice diagnostics; `Main` then deletes any partial user-visible output and quarantines the original input.

## Console representation

Each legacy format uses the common console reporter:

```text
=== <FORMAT> ANALYZER FINDINGS: N ===
<FORMAT> FINDING: ...

<FORMAT> -> <MODERN FORMAT> conversion successful.

=== <FORMAT> FINAL FINDINGS: N ===
<FORMAT> FINAL FINDING: ...
```

This makes the pre-CDR and post-CDR states directly comparable across PDF, DOC/DOCX, PPT/PPTX, and XLS/XLSX.
