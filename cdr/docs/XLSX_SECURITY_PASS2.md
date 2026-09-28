# XLSX Security Pass 2 — Hardening

This pass converts the initial Excel security implementation into a regression-tested security baseline.

### Key changes

1. Formula detection is scoped to actual Excel formula and defined-name elements to reduce false positives from ordinary worksheet text.
2. Active formula sanitization now covers every active function currently classified by `XLSXThreatAnalyzer`, including `EXEC`, `RUN`, `GET.CELL`, `GET.WORKBOOK`, `CALL`, and `REGISTER.ID`.
3. Sanitization preserves cached cell values when an unsafe formula is removed.
4. The common OOXML relationship-reference invariant now applies to DOCX/XLSX/PPTX.
5. Removing an unsafe package part also removes its outgoing relationships and stale explicit content types.
6. Regression tests cover preservation as well as removal.

### Verification

- `XLSXSecuritySurfaceTest`: PASS
- `XLSXHardeningRegressionTest`: PASS
- Clean workbook sample: 0 findings before sanitization; reconstruction/read-back integrity PASS.
- Real `xlsx_embedded_vba.xlsx`: VBA project and relationship detected; sanitized output has no remaining blocking findings and passes OOXML integrity validation.
- All XLSX security test cases verified under `mvn clean test`.
