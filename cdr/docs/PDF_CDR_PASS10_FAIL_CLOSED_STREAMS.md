# PDF CDR Pass 10 — Fail-Closed Stream Inspection

## Security objective

An undecodable PDF stream must never be interpreted as evidence that the stream is safe.

## Change

`PDFStreamThreatInspector` now reports a blocking `UNSUPPORTED_CONTENT` finding whenever a decoded PDF stream cannot be inspected safely, except when the configured resource limit is exceeded, in which case `PDF_RESOURCE_LIMIT` remains the finding.

This covers cases such as unsupported stream filters, malformed/truncated stream data, and other decoder failures.

## Result

The PDF processing pipeline can no longer silently continue from:

```text
stream decoder failure -> no finding -> SAFE
```

It instead follows:

```text
stream decoder failure
        -> UNSUPPORTED_CONTENT / CRITICAL
        -> blocking result
        -> fail closed / quarantine
```

## False-positive trade-off

This pass intentionally prefers quarantine over a false-safe classification when a PDF stream cannot be inspected. A stream that PDFBox cannot decode may be harmless, but DocShield cannot establish that from the available inspection layer.

## Regression test

`PDFStreamThreatInspectorTest.undecodableStreamFailsClosed` creates a stream using an intentionally unknown filter and verifies that it produces a blocking `UNSUPPORTED_CONTENT` finding.
