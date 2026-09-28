# PDF CDR Pass 5 — Reconstruction and Robustness

## Scope

Pass 5 hardens the PDF CDR boundary around reconstruction, signatures, forms and output safety.

## Changes

- Reconstructed PDFs are written to a temporary file in the destination directory before being moved to the requested output path.
- Atomic move is used when supported; a normal replacement move is used when the filesystem does not support atomic moves.
- Existing digital-signature fields/widgets are removed because a fresh CDR serialization cannot preserve their original byte-range signature.
- Ordinary AcroForm fields remain eligible for preservation; XFA remains removed by policy.
- Post-reconstruction validation now forces access to pages, resources, annotations, catalog page tree, names and AcroForm structures.
- Encrypted/password-protected PDFs that cannot be opened are reported as unsafe-to-process rather than being treated as clean.
- The post-reconstruction threat analyzer remains mandatory.

## Safety invariant

A PDF is released only when reconstruction succeeded, the output can be reopened, structural validation passes, and the reconstructed PDF has no blocking security findings.
