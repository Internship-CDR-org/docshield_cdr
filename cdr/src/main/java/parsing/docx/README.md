# Modern DOCX Parser Subsystem (`parsing.docx`)

This package is responsible for parsing Microsoft Word modern Open XML Document formats (`.docx` files).

## 1. Purpose
The purpose of the `parsing.docx` directory is to extract textual content, document metadata, media assets (images), and embedded binary objects from `.docx` files. It translates the zipped Open Packaging Convention layout into the unified `DocumentModel`.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DOCXParser.java` | Main parser driver. Orchestrates text, resource, and metadata parsing, and classifies ZIP files into categories. | `DOCXParser` |
| `DOCXContentParser.java` | Extracts structured text paragraphs and runs using the Apache POI XWPF library. | `DOCXContentParser` |
| `DOCXResourceParser.java` | Scans ZIP entries directly to find media files and embedded OLE elements. | `DOCXResourceParser` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` retrieves a `DOCXParser` when processing `.docx` files.
- `DOCXParser` extracts content using `DOCXContentParser`, scans for media assets using `DOCXResourceParser`, and extracts document/app property maps using the common core/app metadata parsers.

```
                  Input DOCX File
                         │
                         ▼
                     DOCXParser
                         ├─► DOCXResourceParser (Finds media & embeddings)
                         ├─► DOCXContentParser (POI XWPF Text extraction)
                         ├─► CoreMetadataParser & AppMetadataParser (Metadata)
                         ▼
                   DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `model.common`

## 5. External Libraries / APIs
- **Apache POI OOXML (`org.apache.poi.xwpf.usermodel.*`)**: Used to parse structured OOXML word-processing structures. It opens the file stream into `XWPFDocument` and reads through paragraphs, tables, runs, and comments.
- **Java ZIP APIs (`java.util.zip.ZipFile`, `java.util.zip.ZipEntry`)**: Used to perform fast index scans of package structures to identify media resources and document relationships without inflating the entire document.

## 6. Important Classes and Responsibilities
### `DOCXParser`
- **Component Classification**: Iterates over ZIP archive entries and classifies them into:
  - `METADATA`: Entries starting with `docProps/`.
  - `CONTENT`: Main text-bearing elements (`word/document.xml`, `word/footnotes.xml`, `word/endnotes.xml`, `word/comments.xml`).
  - `RELATIONSHIP`: Entries containing `_rels/` or ending in `.rels`.
  - `STRUCTURE`: Layout components (`word/styles.xml`, `word/numbering.xml`, `word/settings.xml`, `word/fontTable.xml`).

### `DOCXResourceParser`
- **Resource Extraction**: Scans ZIP paths and identifies resources by their locations:
  - Any zip entries under `word/media/` are registered as images.
  - Any zip entries under `word/embeddings/` are registered as embedded objects.
