# DocShield Error Handling Guide

DocShield is fail-closed: an input is never released merely because an error occurred. Processing failures remove any partial output and route the original input to quarantine when the application can do so safely.

## Exit codes

| Code | Meaning | Typical cause |
|---:|---|---|
| 0 | Success | Clean input copied unchanged, or threat-bearing input sanitized, reconstructed, and verified. |
| 1 | Operator/input-path error | Invalid arguments, same input/output path, unreadable input, or unwritable destination. |
| 2 | Security/process failure | Unknown or spoofed format, parser failure, conversion failure, integrity failure, residual threat, unsupported/uninspectable content, or quarantine decision. |

## Common messages

### File doesn't exist
**Message:** File doesn't exist: <path>

**Meaning:** The supplied input path does not point to an existing file.

**Action:** Check the path and filename. Do not rename a suspicious file just to make it pass identification.

### Permission denied
**Meaning:** DocShield could not read the input or write the requested output.

**Action:** Verify file and directory permissions. On Windows, also check whether another application has the file locked.

### Unknown or unsupported file format
**Meaning:** The bytes could not be confidently mapped to a supported document format.

**Action:** Keep the original isolated. Verify that the file is complete and that its extension matches its actual content.

### File type mismatch
**Meaning:** The extension does not agree with the detected binary format.

**Action:** Treat this as a security signal. Do not simply rename the extension and retry unless you have independently verified the file.

### Invalid or malformed document structure
**Meaning:** A parser encountered malformed ZIP/XML/PDF/document structures.

**Action:** Keep the original isolated. A malformed document may be intentionally crafted to exploit a parser.

### Unsafe package path / path traversal
**Meaning:** An OOXML ZIP entry attempts to escape the package root or use an unsafe path.

**Action:** Do not open the original manually. DocShield rejects the package before reconstruction.

### Duplicate package entries
**Meaning:** The OOXML archive contains duplicate package paths, including case-insensitive collisions.

**Action:** Treat the package as untrusted and keep the quarantined original.

### Size/resource limit exceeded
**Meaning:** The file, internal package part, converted output, or subprocess output exceeded a configured safety limit.

**Action:** Check configured limits before increasing them. Raising limits increases resource-exhaustion exposure.

### LibreOffice conversion failed
**Meaning:** A legacy DOC/PPT/XLS conversion process returned an error, timed out, produced excessive output, or failed to create the expected modern document.

**Action:** Keep the original quarantined. Check that LibreOffice is installed and available when processing legacy formats. Conversion is deliberately isolated from the main JVM.

### Encrypted/password-protected PDF
**Meaning:** PDFBox could not safely open the document without credentials.

**Action:** Supply a supported password through the documented interface, or quarantine the file if the password is unavailable. Do not bypass PDF encryption by modifying the source file.

### Threat could not be removed
**Meaning:** A blocking security finding remained after sanitization/reconstruction or final security verification.

**Action:** Do not release the generated output. DocShield deletes the partial output and quarantines the input.

### Integrity validation failed
**Meaning:** The reconstructed file could not be proven structurally valid.

**Action:** Do not open or distribute the output. Investigate the validator failure before changing sanitization code.

## Quarantine behavior

When a security/process failure reaches the main application gatekeeper:

1. Any partial output is deleted.
2. The original input is copied into the quarantine area by QuarantineManager.
3. The reason is recorded with the quarantine record.
4. The process exits with code 2.
5. If quarantine itself fails, DocShield explicitly warns the operator to keep the original isolated and not open it.

## Error-message design

Internal exceptions are intentionally not printed as raw stack traces to normal operators. application.UserFacingError maps low-level failures into actionable categories while preserving the underlying reason in the quarantine/audit path where appropriate.

When adding a new security control:

- give it a precise exception message;
- make the message identify the failing stage;
- distinguish operator errors from input-security failures;
- add a regression test for the public-facing message;
- document the message and remediation here.

## Troubleshooting order

1. Confirm the command-line arguments.
2. Confirm the input exists and is readable.
3. Confirm the output directory is writable.
4. Confirm the extension matches the actual file type.
5. For DOC/PPT/XLS, confirm the LibreOffice conversion dependency.
6. Read the quarantine/audit record.
7. Only then investigate parser, sanitizer, reconstruction, or validator code.

Never weaken a security check merely to make a malformed or suspicious document process successfully.
