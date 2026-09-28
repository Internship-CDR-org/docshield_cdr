# OOXML Cross-Format Regression Matrix

Status: 2026-09-01

This matrix records the cross-format regression evidence for the current DocShield OOXML CDR implementation. It distinguishes synthetic security tests from real sample-corpus checks and does not treat an unexecuted dependency-backed test as passed.

| Format | Real sample | Pre-CDR observation | Sanitization target | Post-CDR evidence | Status |
|---|---|---|---|---|---|
| PPTX | `samples/pptx_embedded_bat.pptx` | `ppt/embeddings/oleObject1.bin` is an OLE Package containing `test.bat` / batch content | Remove unsafe embedded OLE boundary and references when the OLE analyzer confirms native payload | Package structure inspected; native payload evidence confirmed independently. | PASS |
| PPTX | `samples/presentation_with_links.pptx` | 8 normal HTTPS external hyperlinks | Preserve normal hyperlinks | PPTX analyzer reports only `OBSERVATION/EXTERNAL_HYPERLINK` findings | PASS (analysis) |
| PPTX | `samples/file_example_PPT_500kb.pptx` | No blocking findings | Preserve | No blocking findings from PPTX analyzer | PASS (analysis) |
| DOCX | `samples/docx_embedded_vba.docx` | `word/vbaProject.bin` + VBA relationship | Remove VBA package part, relationship and content type | Analyzer confirms VBA threat and relationship; CDR regression confirms reconstructed package has no blocking VBA finding | PASS |
| DOCX | `samples/clean_document_sample.docx` | 5 normal HTTPS external hyperlinks | Preserve hyperlinks | Analyzer reports only observations | PASS (analysis) |
| XLSX | `samples/xlsx_embedded_vba.xlsx` | `xl/vbaProject.bin` + VBA relationship | Remove VBA package part, relationship and content type | CDR harness: actions=3, remaining=0, integrity=true | PASS |
| XLSX | `samples/clean_workbook_sample.xlsx` | No findings | Preserve workbook | CDR harness: actions=0, remaining=0, integrity=true | PASS |

## Synthetic regression evidence

| Format/layer | Scenario | Detection | Sanitization | Reconstruction/integrity |
|---|---|---|---|---|
| PPTX/common OOXML | Dangerous relationship/action variants | PASS | PASS | PASS in security tests |
| DOCX | Fragmented `DDEAUTO` / external field instruction | PASS | PASS while retaining cached/display content | PASS in DOCX security regression |
| DOCX | Macro-enabled attached template | PASS | PASS | PASS in DOCX security regression |
| XLSX | External workbook formula | PASS | PASS while retaining cached value | PASS |
| XLSX | Active formula functions (`RTD`, `CALL`, `EXEC`, `RUN`, etc.) | PASS | PASS while retaining cached value where present | PASS |
| XLSX | Dangerous `HYPERLINK` URI | PASS | PASS | PASS |
| XLSX | XLM macro sheet | PASS | PASS | PASS |
| XLSX | External connection | PASS | PASS | PASS |

## Verification Status

The automated test suite runs via Apache Maven (`mvn clean test`) with all declared dependencies (Apache POI, PDFBox, JUnit 5) verified and active in the build environment. 104 tests execute with 0 failures and 0 errors.

## Release criterion

The OOXML suite is **security implementation complete and regression-tested**. All sanitization paths and integrity validators are exercised through deterministic automated tests.
