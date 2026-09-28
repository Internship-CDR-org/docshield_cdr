# PDF CDR Pass 4 — Robustness and Fail-Closed Hardening

Pass 4 strengthens the PDF CDR boundary without weakening preservation of ordinary page content.

## Safety controls

- Centralized PDF security limits in `PDFSecurityPolicy`.
- Maximum input size: 200 MiB.
- Maximum pages: 10,000.
- Maximum COS objects traversed: 200,000.
- Maximum embedded payload: 64 MiB.
- Maximum embedded payloads inspected: 256.
- Object-graph traversal now reports a blocking `PDF_RESOURCE_LIMIT` finding when the inspection budget is exceeded instead of silently stopping.
- Post-reconstruction verification repeats both PDF analysis and embedded-payload inspection.
- Inputs exceeding safety limits fail closed; no reconstructed output is released.

## URI normalization

Dangerous URI detection strips leading control/whitespace characters and applies up to three percent-decoding rounds before scheme matching. This blocks simple encoded-scheme obfuscation while ordinary HTTP/HTTPS links remain allowed.

## Encrypted and signed PDFs

Encrypted PDFs are reconstructed only when PDFBox can safely open them with the available credentials. CDR output is written without source encryption. Digital signatures cannot remain valid after fresh reconstruction; signature material is therefore treated as a policy violation and disarmed.

## Validation

The Maven/JUnit suite must be run in an environment with project dependencies available. This pass does not claim runtime test success when those dependencies are unavailable.
