# PDF Stream Security Hardening

## Why this pass exists

The PDF security analyzer previously focused on the PDF object graph: actions, annotations, form mechanisms, name trees, filespecs and other security-relevant dictionaries. That leaves a separate blind spot: arbitrary decoded PDF streams can carry payload bytes without being exposed through a `Filespec` or active-content dictionary.

This pass adds a complementary byte-level stream inspection layer.

## Detection model

The new `PDFStreamThreatInspector` walks the catalog, pages and recursively reachable dictionaries/arrays and inspects decoded `COSStream` bytes. It deliberately uses high-confidence signatures rather than malware-family names.

Currently blocked signatures include:

- EICAR antivirus-test marker.
- DOS/PE `MZ` executable signature.
- ELF executable signature.
- Mach-O executable signatures.
- Executable-script shebangs for common interpreters.

The stream limit is bounded by the existing PDF embedded-payload byte limit, and traversal remains bounded by the existing PDF object budget.

## Sanitization

When an executable stream signature is found, `PDFThreatSanitizer` truncates that stream before reconstruction. This is intentionally narrower than deleting every binary/image/font stream: ordinary PDF resources are preserved unless a high-confidence executable payload is identified.

## Important limitation

This is not a malware scanner and it is not a claim of zero false negatives. Malware can be represented as exploit data, obfuscated script, malformed PDF syntax, encrypted/encoded content, or a payload whose semantics require a PDF-specific vulnerability model. Real false-safe PDFs from the external VirusTotal comparison are required to identify those exact structures and add regression coverage.

The next validation target should therefore be a small corpus of the PDFs that DocShield previously classified as safe but VirusTotal flagged, especially the samples associated with `PDF/IcedID`, `PDF/Agent.PE`, `Scr.Malcode`, and `Scr.DLHeur`.
