# PDF CDR Pass 9 — XRef/Object-Pool Stream Coverage

## Purpose

Pass 9 closes a PDF inspection blind spot where a decoded stream is present in the parsed PDF xref/object pool but is not reached through the normal catalog/page graph.

The PDF stream inspector now performs two complementary traversals:

1. Normal catalog/page/object-graph traversal.
2. Parsed xref/object-pool traversal through PDFBox 3.x `COSDocument.getXrefTable()` and `getObjectFromPool(...)`.

The second pass is especially relevant to PDFs using indirect objects and compressed/object-stream representations.

## Security behavior

High-confidence executable signatures discovered through either traversal are reported as `EXECUTABLE_PAYLOAD` and therefore remain blocking findings.

The PDF sanitizer mirrors the xref/object-pool traversal and neutralizes executable streams it discovers, so detection is not separated from remediation.

If xref/object-pool inspection itself cannot be completed, the inspector records an `UNSUPPORTED_CONTENT` finding instead of silently treating the document as safe.

## Regression coverage

`PDFStreamThreatInspectorTest` includes a synthetic PDF containing a structurally valid PE payload in an xref-listed stream that is not linked from the page graph. The test verifies both detection and sanitization.

## Scope

This pass does **not** treat ordinary PDF filters, images, fonts, or page-content streams as malicious merely because they use compression or uncommon encodings. It adds coverage for object placement/traversal first; more specialized obfuscation analysis should be driven by real guide test results to avoid unnecessary false positives.

## Validation

Run:

```bash
mvn clean test
```

Do not push the pass if the Maven build or regression suite fails.
