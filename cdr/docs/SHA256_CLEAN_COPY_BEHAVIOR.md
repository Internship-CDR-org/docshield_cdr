# SHA-256 and Clean-File Copy Behavior

## Policy

DocShield preserves the original bytes when the complete security analysis finds no blocking threat or policy violation. A clean file is copied byte-for-byte to the requested output path instead of being parsed, saved, or reconstructed again.

Therefore, for a clean same-format input:

`SHA-256(input) == SHA-256(output)`

For a file with a blocking threat, DocShield sanitizes and reconstructs the output. The reconstructed artifact is expected to have a different SHA-256 value.

Processing failures, unsupported security-relevant content, and failed post-CDR verification remain fail-closed and must not be released as a clean original.

## Result metadata

`CDRResult` records:

- `inputSha256`
- `outputSha256`
- `originalCopied`
- reconstruction status

The command-line summary and generated report expose these values.
