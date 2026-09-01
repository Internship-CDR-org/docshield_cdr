# File Identification Subsystem (`identification`)

This package is responsible for safely detecting the format and extracting basic metadata from files before any parsing is attempted.

## 1. Purpose
The purpose of the `identification` directory is to inspect input files, verify their format using binary magic numbers (signatures) rather than relying solely on file extensions, calculate cryptographic hashes (SHA-256), and determine if the extension matches the actual binary content. This prevents extension-spoofing attacks.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `Format.java` | Defines the supported document formats in DocShield. | `Format` (enum) |
| `FileInfo.java` | Read-only container storing filename, size, extension, MIME type, SHA-256 hash, detected `Format`, validity status, and extension mismatch flags. | `FileInfo` |
| `FileIdentifier.java` | Implements signature checking (magic bytes) and checks zip archives internally to distinguish DOCX, PPTX, and XLSX formats. | `FileIdentifier` |

## 3. How the Directory Fits into DocShield
This is the first step in the DocShield CDR pipeline. `Main` invokes `FileIdentifier` to determine the format. The resulting `FileInfo` object is then used to select the parser and CDR processor.

```
Input File Path
       │
       ▼
FileIdentifier.identify()
       │
       ├─► Read header bytes (verify magic signature)
       ├─► Inspect OOXML zip structures (Content_Types.xml, main XML parts)
       ├─► Calculate SHA-256 hash
       │
       ▼
FileInfo (Format, validity status, etc.)
       │
       ▼
Main (Routes to ParserFactory)
```

## 4. Dependencies
- Standard Java libraries only. No internal project dependencies.

## 5. External Libraries / APIs
- **Java Cryptography API (`java.security.MessageDigest`)**: Used to calculate the SHA-256 checksum of files.
- **Java ZIP APIs (`java.util.zip.ZipFile`, `java.util.zip.ZipEntry`)**: Used to probe ZIP archives to verify OOXML structure (detect presence of `[Content_Types].xml`, `word/document.xml`, `ppt/presentation.xml`, and `xl/workbook.xml`).

## 6. Important Classes and Responsibilities
### `FileIdentifier`
- **Signature Detection**: Probes the beginning of the file to match magic headers:
  - `%PDF-` -> `PDF`
  - `{\rtf` -> `RTF`
  - `D0 CF 11 E0 A1 B1 1A E1` -> OLE compound binary files (DOC, PPT, XLS).
  - `PK\x03\x04` -> ZIP files, which are scanned deeper for OOXML structure.
- **OOXML Deep Probe**: Scans ZIP entries inside the file to identify the exact Office Open XML format:
  - `word/document.xml` present -> `DOCX`
  - `ppt/presentation.xml` present -> `PPTX`
  - `xl/workbook.xml` present -> `XLSX`
- **Hash calculation**: Safely reads the file in chunks to compute the SHA-256 string.

## 7. Important Design Decisions
- **Anti-Spoofing Verification**: The system checks if the detected magic-number format matches the file extension. If there is a mismatch (e.g., a PDF file renamed to `.docx`), the file is marked as invalid (`valid = false`, `extensionMatch = false`), which prevents parsing spoofed files.
- **OLE Extension Fallback**: For legacy OLE formats (DOC, PPT, XLS), which share the same binary header structure, the identifier relies on the file extension to distinguish the subformat.

## 8. Example Usage
```java
FileIdentifier identifier = new FileIdentifier();
FileInfo info = identifier.identify(Path.of("test.pptx"));

System.out.println("Format: " + info.getFormat()); // PPTX
System.out.println("SHA-256: " + info.getSha256());
System.out.println("Is Valid: " + info.isValid());
```
