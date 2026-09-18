# Secure OOXML Package Reader (`parsing.ooxml`)

The `parsing.ooxml` package provides the secure Open Packaging Conventions (OPC / OOXML) archive ingestion engine used across `DOCX`, `PPTX`, `XLSX`, and nested embedded packages.

---

## 1. Architectural Purpose

Modern Microsoft Office documents are ZIP archives containing XML parts, binary resources, relationship graphs (`.rels`), and a root content type registry (`[Content_Types].xml`). Ingesting untrusted ZIP packages directly with standard libraries exposes the host to ZIP bombs, directory traversal overwrites (Zip Slip), XML External Entity (XXE) attacks, and duplicate entry confusion.

[`OOXMLPackageReader`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ooxml/OOXMLPackageReader.java) implements a hardened, stream-verified reader that builds an in-memory [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) data structure under strict resource and safety constraints.

---

## 2. Configured Resource Limits & Security Bounds

| Control | Constant | Exact Limit | Threat Neutralized |
|---|---|---|---|
| **Max ZIP Entries** | `MAX_ZIP_ENTRIES` | `10,000` entries | ZIP entry inflation / denial of service |
| **Max Uncompressed Bytes** | `MAX_TOTAL_UNCOMPRESSED_BYTES` | `256 MB` (`268,435,456` bytes) | Archive decompression bombs |
| **Max Single Part Size** | `MAX_SINGLE_PART_BYTES` | `128 MB` (`134,217,728` bytes) | Single-stream memory exhaustion |

---

## 3. Structural Protections in `OOXMLPackageReader`

1. **Path Safety & Traversal Prevention**:
   - Every ZIP entry name is verified through [`PathSandbox.isSafeZipEntryName`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/sandbox/PathSandbox.java).
   - Rejects entries with path traversal tokens (`..`), leading slashes (`/`), drive prefixes (`C:`), Windows backslashes (`\`), or null bytes (`\0`).
2. **Duplicate Entry Rejection**:
   - Tracks seen entry names (normalized case-insensitively).
   - Throws an `IOException` if duplicate ZIP entries are detected, eliminating ZIP parser differential attacks.
3. **Hardened XML Deserialization**:
   - All relationship files (`.rels`) and `[Content_Types].xml` are parsed using [`SecureXmlFactory`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/sandbox/SecureXmlFactory.java) `DocumentBuilderFactory`.
   - `DOCTYPE` declarations are disallowed (`disallow-doctype-decl = true`).
   - External entities and DTDs are disabled (`external-general-entities = false`, `external-parameter-entities = false`).
   - XInclude and entity expansion are disabled.
4. **Relationship Target Normalization**:
   - Normalizes relative relationship targets against the owning source part (e.g., `../media/image1.png` relative to `word/document.xml` resolves to `word/media/image1.png`).
   - Validates that internal relationship targets do not escape the package root.
