# Legacy DOC Parser Subsystem (`parsing.doc`)

This package is responsible for parsing legacy Microsoft Word binary documents (`.doc` files) in OLE Compound Document Format.

## 1. Purpose
The purpose of the `parsing.doc` directory is to extract text, metadata, images, and embedded objects from legacy `.doc` files. Due to the complexity and instability of parsing old binary formats, this subsystem implements a robust dual-path strategy: attempting native library parsing first and falling back to external headless conversion when needed.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DOCParser.java` | Main driver for DOC documents. Coordinates native HWPF parsing, validation, and fallback conversion. | `DOCParser` |
| `DOCContentParser.java` | Extracts text paragraphs and ranges using the Apache POI HWPF library. | `DOCContentParser` |
| `DOCMetadataParser.java` | Extracts document properties (OLE SummaryInformation). | `DOCMetadataParser` |
| `DOCResourceParser.java` | Extracts binary images and OLE-embedded objects. | `DOCResourceParser` |
| `DOCParseResult.java` | Keeps track of extraction statistics and fallback details. | `DOCParseResult` |
| `DOCExtractionValidator.java` | Validates if the native parser extracted sufficient content to be considered successful. | `DOCExtractionValidator` |
| `DOCToDOCXConverter.java` | Spawns a LibreOffice command-line subprocess to convert DOC files into DOCX format. | `DOCToDOCXConverter` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` returns `DOCParser` when the detected format is `DOC`.
- The parser tries native POI HWPF parsing first.
- If POI extraction fails or is validated as empty (empty text, zero images, zero objects), `DOCParser` invokes `DOCToDOCXConverter`.
- The converter converts the document to DOCX using LibreOffice.
- `DOCParser` then runs `DOCXParser` on the converted file and deletes the temporary file afterwards.

```
                   Input DOC File
                         │
                         ▼
                     DOCParser
                         │
             ┌───────────┴───────────┐
             ▼ (Native Path)         │
       parseUsingHWPF                │
             │                       │
             ▼                       ▼ (Fallback Path on Failure/Empty)
    DOCExtractionValidator ──────► parseUsingDOCXFallback
      (Check text/image/obj)         │
             │                       ├─► DOCToDOCXConverter (LibreOffice CLI)
             ▼ (Pass)                ├─► DOCXParser (Parses temporary DOCX)
        DocumentModel                ├─► Delete temporary files
                                     ▼
                               DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `parsing.docx`
- `model.common`

## 5. External Libraries / APIs
- **Apache POI Scratchpad (`org.apache.poi.hwpf.*`)**: Used for native parsing of the binary DOC structure (extracting document text ranges, character runs, and OLE tables).
- **LibreOffice CLI (`libreoffice`)**: Headless subprocess tool used as a fallback parser by converting DOC binary streams to modern DOCX files.

## 6. Important Classes and Responsibilities
### `DOCParser`
- **Fallback Execution**: Coordinates the execution paths. It catches POI runtime failures, logs validation details to `DOCParseResult`, and routes to the fallback path.

### `DOCToDOCXConverter`
- **Subprocess Management**: Builds a `ProcessBuilder` with `libreoffice --headless --convert-to docx --outdir <temp-dir> <input-file>`. Reads process input streams and awaits completion.

### `DOCExtractionValidator`
- **Sanity Audits**: Evaluates `DOCParseResult` metrics. If the native extractor found zero text characters, images, and embedded objects, it declares the extraction invalid, triggering fallback.

## 7. Important Design Decisions
- **Robustness via Headless Subprocess Fallback**: If the native OLE parser fails or produces a silent empty output, the engine falls back to headless LibreOffice conversion to avoid data loss.
- **Resource Cleanup**: When fallback conversion is used, the temporary directory and converted DOCX file are deleted immediately after parsing.
