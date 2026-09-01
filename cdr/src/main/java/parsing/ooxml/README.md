# Generic OOXML Package Reader Subsystem (`parsing.ooxml`)

This package is responsible for reading Open Packaging Convention (OPC) / Office Open XML (OOXML) file packages at the zip container level.

## 1. Purpose
The purpose of the `parsing.ooxml` directory is to provide a generic, format-independent parser (`OOXMLPackageReader`) that unzips modern Office files and constructs the basic `OOXMLPackage` physical structure. It reads files, overrides/default content type mappings, and parses relationships securely, protecting the engine from XML Entity vulnerabilities.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `OOXMLPackageReader.java` | Main class that reads files from the zip stream, extracts content types, and processes relationships. | `OOXMLPackageReader` |

## 3. How the Directory Fits into DocShield
- This is the standard physical package parser used in the processing layer for DOCX and XLSX documents.
- `DOCXCDRProcessor` and `XLSXCDRProcessor` call `OOXMLPackageReader.read(file)` to load raw zip streams before sanitizing individual parts.

```
       Input DOCX / XLSX File
                 │
                 ▼
         OOXMLPackageReader
          ├─► Scans zip entries and extracts raw byte data
          ├─► Parses [Content_Types].xml (MIME overrides)
          └─► Parses .rels relationship files (XXE-secured XML parsing)
                 │
                 ▼
            OOXMLPackage ──► Threat Sanitizer
```

## 4. Dependencies
- `model.ooxml`

## 5. External Libraries / APIs
- **Java XML DOM APIs (`javax.xml.parsers.DocumentBuilderFactory`)**: Reads package descriptors (`[Content_Types].xml` and relationship files `.rels`).
- **Java ZIP APIs (`java.util.zip.ZipFile`)**: Accesses ZIP file structures directly.

## 6. Important Design Decisions
- **Unified XML Parsing Protections (XXE)**: To prevent XML External Entity injection (XXE) and XML Entity Expansion attacks (Billion Laughs), the XML parsing helper enforces:
  - `disallow-doctype-decl` = `true` (disallows DOCTYPE declarations).
  - `external-general-entities` = `false` (disables external general entities).
  - `external-parameter-entities` = `false` (disables external parameter entities).
  - `xincludeAware` = `false` (disables XInclude).
  - `expandEntityReferences` = `false` (disables entity expansion).
- **Target Part Resolution**: Maps relative relationship targets back to their parent files (e.g. converting `ppt/slides/_rels/slide1.xml.rels` destination `../drawings/drawing1.xml` to `ppt/drawings/drawing1.xml`).
