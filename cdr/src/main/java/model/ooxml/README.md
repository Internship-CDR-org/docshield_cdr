# Open XML Package Model (`model.ooxml`)

This package provides generic, format-independent object models to represent the structure of an Open Packaging Convention (OPC) / Office Open XML (OOXML) package.

## 1. Purpose
The purpose of the `model.ooxml` directory is to represent an OOXML file as a structured zip container of logical parts (files), relationships (mappings between files), and content types. It enables the disarming engine to inspect and reconstruct zip packages at a physical file and relationship level without needing to understand word processing, presentation, or spreadsheet semantic details.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `OOXMLPackage.java` | Acts as the memory model of the entire OOXML ZIP container, keeping track of logical parts, relationship tables, and type mappings. | `OOXMLPackage` |
| `OOXMLPart.java` | Represents a single file entry in the zip package (e.g., XML files, images, embedded OLE objects). Keeps the raw byte array data. | `OOXMLPart` |
| `OOXMLRelationship.java` | Represents a single logical connection (defined in `.rels` files) between parts or from the package root to parts. | `OOXMLRelationship` |

## 3. How the Directory Fits into DocShield
This is the physical foundation for the OOXML (DOCX, PPTX, XLSX) processing pipeline:
- `OOXMLPackageReader` (in parsing) reads the physical ZIP file and creates an `OOXMLPackage` instance.
- Sanitizers inspect this package, removing dangerous parts (such as macros or embedded EXE files) and editing or removing relationship entries.
- `OOXMLPackageWriter` (in reconstruction) serializes the `OOXMLPackage` back into a valid ZIP archive.

```
       Zip File
          │
          ▼ (Reads via ZipInputStream)
  OOXMLPackageReader
          │
          ▼ (Constructs)
     OOXMLPackage ◄──► Threat Sanitizer (Inspects/Modifies parts)
          │
          ▼ (Writes via ZipOutputStream)
  OOXMLPackageWriter
          │
          ▼
     Sanitized Zip
```

## 4. Dependencies
- Standard Java libraries only.

## 5. External Libraries / APIs
None. Standard JDK libraries only (`java.util.LinkedHashMap`, `java.util.ArrayList`, etc.).

## 6. Important Classes and Responsibilities
### `OOXMLPackage`
- **Part Management**: Provides registry methods to add, retrieve, check, and delete `OOXMLPart` instances by name.
- **Relationship Management**: Keeps a registry of `OOXMLRelationship` entries and supports removing relationships originating from specific parts (e.g., removing a slide's connection to an embedded object).
- **Content Types**: Manages mappings of extensions (e.g., `.xml`, `.png`) or specific override part names to their respective MIME types.
- **Part Name Normalization**: Cleanses filenames to ensure consistent UNIX-style paths (`/` instead of `\`) and strip leading/trailing spaces or slashes.

### `OOXMLPart`
- **Data Preservation**: Holds raw file bytes (`byte[] data`), protecting the original binary structure (such as images, layouts, shapes) from corruption.
- **XML Detection**: Automates detection of XML files by checking if the content type contains the substring `xml`.

### `OOXMLRelationship`
- **External Target Detection**: Provides `isExternal()` to determine if a relationship points to a resource outside the package (e.g., an external URL, which might indicate a remote template injection vulnerability).

## 7. Important Design Decisions
- **Raw Byte Preservation**: Maintains exact, unmodified data byte arrays of all document parts in memory. Only components identified as threats are disarmed, while non-threatening components are written out byte-for-byte as they were read, preserving original metadata, styling, and vendor-specific data structures.
- **Unified Package Abstraction**: Since DOCX, PPTX, and XLSX are all OPC zip files, they reuse this package structure, sharing the base code for reader, writer, and package validation.
