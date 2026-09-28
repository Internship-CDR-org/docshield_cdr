# CDR Console and Report Finding Flow

Every implemented CDR processor exposes the same two security snapshots:

1. **Analyzer Findings** — findings discovered before sanitization/reconstruction.
2. **Final Findings** — findings discovered by re-opening the reconstructed output and running the applicable security analyzer again.

The final snapshot is the post-CDR verification result. A zero-count final snapshot means no remaining blocking finding was detected by the applicable analyzer. The `threatsRemoved` result is still evaluated using the processor's format-specific and recursive safety checks.

## Console format

Each format uses the same structure:

```text
=== FORMAT ANALYZER FINDINGS: N ===
FORMAT FINDING: CLASSIFICATION | TYPE | DESCRIPTION

=== FORMAT FINAL FINDINGS: N ===
FORMAT FINAL FINDING: CLASSIFICATION | TYPE | DESCRIPTION
```

For example, a detected VBA project in a legacy DOC may be reported before conversion, followed by `DOC FINAL FINDINGS: 0` after DOC-to-DOCX conversion, sanitization, reconstruction and re-analysis.

## Reports

`CDRResult` stores the two snapshots separately. The report contains:

- `SECURITY FINDINGS` — original/pre-CDR findings
- `POST-CDR FINAL FINDINGS` — findings remaining after reconstruction and re-analysis
- `SANITIZATION` — actions performed, including legacy-format disarming performed by the conversion boundary when applicable
- `RECONSTRUCTION` — reconstruction and integrity status

This distinction is important for legacy formats because a conversion engine may remove active content before the modern-format analyzer runs. For DOC, the legacy binary document is inspected first so a macro is not incorrectly reported as absent merely because LibreOffice removed it during conversion.
