# PDF CDR Pass 3 — Embedded Payload Boundary Hardening

## Policy

PDF embedded files are treated as an untrusted payload boundary. Before the
outer PDF sanitizer removes the attachment boundary, DocShield inspects the
embedded bytes when the payload is a supported PDF or OOXML document.

- Embedded PDF: recursively analyzed for blocking PDF active content.
- Embedded DOCX/PPTX/XLSX: analyzed with the corresponding OOXML analyzer.
- Unsupported/unknown embedded payload: fail closed and classify it as unsafe.
- All PDF embedded-file payloads are removed by the outer PDF sanitizer in this
  pass. This intentionally avoids byte-level rewriting of arbitrary PDF file
  specifications/attachments until the nested-PDF re-embedding path can be
  runtime-tested with the exact PDFBox version used by the project.

## Safety boundaries

- 64 MiB maximum decoded embedded payload.
- 256 embedded payloads per PDF.
- Payload inspection is non-mutating.
- The original PDF is never overwritten.
- The reconstructed PDF is reopened and re-analyzed.
- Any remaining blocking content causes the output to be rejected/quarantined.

## Rationale

Removing the containing attachment is the fail-closed action. We do not claim
that an embedded file is safe merely because its filename or MIME type looks
benign, and we do not perform unvalidated byte-level surgery inside arbitrary
PDF attachment structures.
