# DocShield Threat Model

## 1. Scope & Assumptions

### 1.1 In-Scope Assets
- Host operating system and filesystem.
- End-user endpoints opening CDR-processed files.
- Enterprise boundary gateways and email relays.
- Integrity of sanitized document outputs.

### 1.2 Out-of-Scope Assets
- Content meaning or truthfulness of document text.
- Visual interpretation of complex raster images.
- Decryption of files where passwords are not provided.

### 1.3 Adversary Model
We assume an adversary who:
- Can construct arbitrarily malformed binary files and valid documents containing malicious active content.
- Can craft documents designed to trigger parser bugs (buffer overflows, memory exhaustion, infinite loops, XXE).
- Can embed multi-layered weaponized documents inside nested OLE or OOXML containers.
- Can manipulate document metadata, MIME types, and file extensions.

---

## 2. Attack Vectors & Mitigations

| Attack Vector | Threat Description | DocShield Mitigation |
|---|---|---|
| **Archive Exploitation** | Zip Slip, directory breakout, path traversal via relative `..` segments. | `PathSandbox.assertSafeZipEntry()` rejects all directory traversal, absolute, null, or drive specifiers. |
| **Resource Depletion** | Zip bombs, recursive expansion loops, oversized XML parts. | Strict caps on ZIP entry counts (10,000), single part size (128 MB), and total uncompressed bytes (256 MB). |
| **XML Exploits** | XXE, SSRF via external DTDs, Billion Laughs entity expansion. | `SecureXmlFactory` enforces DOCTYPE disallowance and disables all external entity expansion. |
| **Macro Exploits** | VBA macro execution, XLM 4.0 macrosheet execution. | Complete removal of VBA projects, macro relationships, and XLM macrosheets from the document package. |
| **Command Injection** | DDE / DDEAUTO execution in Word, Excel, and RTF documents. | Surgical stripping of DDE field instructions and Excel command formulas. |
| **Template Hijacking** | Remote template injection via Word `attachedTemplate` or RTF `\template`. | Removal of external template relationships and RTF template control words. |
| **PDF Exploits** | Malicious JavaScript, auto-launch actions, embedded malware attachments, XFA forms. | COS graph sanitization strips `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, and `/XFA`. |
| **Executable Payloads** | Native executables (`.exe`, `.dll`, `.bat`, `.ps1`, ELF) disguised in stream objects or OLE packages. | Inspection of decoded streams and OLE objects for binary fingerprints; neutralization of payload parts. |
| **Dangerous URIs** | Hyperlinks referencing `file:`, `javascript:`, `powershell:`, `ms-msdt:`, `cmd:`, UNC shares. | Scheme validation neutralizes non-approved URI schemes while preserving benign HTTP/HTTPS/mailto links. |
| **Legacy Format Exploitation** | Binary buffer overflows in legacy Word/Excel/PowerPoint parsers (e.g. CVE-2017-11882). | Isolated, ephemeral subprocess conversion with strict sandboxing and timeouts, preceded by structural threat analysis. |

---

## 3. Residual Risks & Non-Goals

1. **Zero-Day Sandbox Escapes**: While Bubblewrap and subprocess supervision provide defense-in-depth, extreme zero-days in kernel namespace isolation or process management remain theoretical residual risks of the host OS.
2. **Semantic Phishing**: DocShield disarms technical exploit mechanisms; it does not analyze the text content for social engineering or psychological deception.
3. **Lossy Conversions**: Disarming active controls (e.g. dynamic macros or interactive form scripts) intentionally renders those automated features non-functional to guarantee security.
