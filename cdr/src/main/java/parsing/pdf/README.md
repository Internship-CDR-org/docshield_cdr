# PDF Parser Subsystem (`parsing.pdf`)

This package is responsible for parsing Portable Document Format (`.pdf` files).

## 1. Purpose
The purpose of the `parsing.pdf` directory is to parse PDF documents, extracting their textual content, structural nodes, metadata, form fields, images, hyperlinks, interactive events, and embedded attachments, then compiling this information into the unified `DocumentModel`.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `PDFParser.java` | Core driver. Coordinates text extraction, metadata reading, forms, images, interactive links/threats, and structure nodes. | `PDFParser` |
| `PDFContentParser.java` | Uses PDFBox text stripping tools to extract text runs and characters, creating `TextComponent`s. | `PDFContentParser` |
| `PDFMetadataParser.java` | Extracts document information dictionary values (Title, Author, Subject, etc.). | `PDFMetadataParser` |
| `PDFFormParser.java` | Extracts AcroForm fields and layouts. | `PDFFormParser` |
| `PDFResourceParser.java` | Iterates over page resource dictionaries (XObject maps) to discover and extract inline images. | `PDFResourceParser` |
| `PDFInteractiveParser.java` | Scans annotations (Links, Widgets) and actions (URI, JavaScript, Launch) to capture links and flag suspicious threats. | `PDFInteractiveParser` |
| `PDFEmbeddedParser.java` | Queries the document's catalog for EmbeddedFiles (attachments) and extracts them. | `PDFEmbeddedParser` |
| `PDFStructureParser.java` | Extracts document page counts, dimensions, and visual layouts. | `PDFStructureParser` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` resolves the `PDFParser` when processing a `.pdf` file.
- The parser makes modular calls to extraction helpers (e.g., content parser, resource parser, interactive parser) and inserts the results into the `DocumentModel`.

```
                  Input PDF File
                         │
                         ▼
                     PDFParser
                         ├─► PDFContentParser (Text runs)
                         ├─► PDFMetadataParser (Document Info)
                         ├─► PDFFormParser (AcroForm fields)
                         ├─► PDFResourceParser (XObject Images)
                         ├─► PDFInteractiveParser (Actions & Hyperlinks)
                         ├─► PDFEmbeddedParser (Embedded files / Attachments)
                         └─► PDFStructureParser (Pages & Outlines)
                         ▼
                   DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `model.common`

## 5. External Libraries / APIs
- **Apache PDFBox (`org.apache.pdfbox.pdmodel.*`)**: Used to read PDF data structures. Key components include:
  - `PDDocument` to open and close document handles.
  - `PDFTextStripper` to extract formatted character positioning.
  - `PDDocumentCatalog` to query form domains, outlines, and embedded file directories.
  - `PDResources` to inspect graphic parameters.

## 6. Important Classes and Responsibilities
### `PDFInteractiveParser`
- **Link Extraction**: Parses `PDAnnotationLink` items to resolve click destinations.
- **Threat Tagging**: Inspects action dictionaries. Action types like JavaScript (`/JS`), Launch (`/Launch`), or ImportData (`/ImportData`) are flagged and translated into `ThreatComponent` instances inside the model.

### `PDFEmbeddedParser`
- **Attachment Extraction**: Scans the names dictionary (`PDDocumentNameDictionary`) and parses document attachments (`PDEmbeddedFilesNameTreeNode`), saving the files as `EmbeddedObjectComponent` records.
