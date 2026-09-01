# Legacy PPT Parser Subsystem (`parsing.ppt`)

This package is responsible for parsing legacy Microsoft PowerPoint binary presentation formats (`.ppt` files).

## 1. Purpose
The purpose of the `parsing.ppt` directory is to extract text, slides structure, metadata properties, images, hyperlinks, and nested embedded attachments from legacy `.ppt` files. It employs a dual-path design: attempting native POI HSLF parsing first, and falling back to headless LibreOffice conversion if native parsing is incomplete or fails.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `PPTParser.java` | Main driver class. Manages native POI HSLF parsing, result validation, and fallback conversion. | `PPTParser` |
| `PPTContentParser.java` | Extracts text from slides and notes pages using Apache POI HSLF APIs. | `PPTContentParser` |
| `PPTMetadataParser.java` | Extracts OLE metadata properties. | `PPTMetadataParser` |
| `PPTResourceParser.java` | Extracts presentation images and embedded objects. | `PPTResourceParser` |
| `PPTHyperlinkExtractor.java` | Extracts hyperlinks from slide text runs and action shapes. | `PPTHyperlinkExtractor` |
| `PPTStructureParser.java` | Inspects slides to map shape hierarchy, slide names, and layout dimensions. | `PPTStructureParser` |
| `PPTParseResult.java` | Container for parse logs, counts, and conversion fallback history. | `PPTParseResult` |
| `PPTExtractionValidator.java` | Assesses if native POI HSLF extraction extracted sufficient data. | `PPTExtractionValidator` |
| `PPTToPPTXConverter.java` | Spawns a headless LibreOffice subprocess to convert legacy PPT to modern PPTX. | `PPTToPPTXConverter` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` returns `PPTParser` when processing `.ppt` formats.
- The parser executes the native HSLF path.
- If HSLF fails or is validated as empty by `PPTExtractionValidator`, `PPTParser` calls `PPTToPPTXConverter` to generate a temporary PPTX file.
- It then processes the converted file using `PPTXParser` and deletes the temporary file afterwards.

```
                   Input PPT File
                         │
                         ▼
                     PPTParser
                         │
             ┌───────────┴───────────┐
             ▼ (Native Path)         │
       parseUsingHSLF                │
             │                       │
             ▼                       ▼ (Fallback Path on Failure/Empty)
    PPTExtractionValidator ──────► parseUsingPPTXFallback
      (Check text/image/obj)         │
             │                       ├─► PPTToPPTXConverter (LibreOffice CLI)
             ▼ (Pass)                ├─► PPTXParser (Parses temporary PPTX)
        DocumentModel                ├─► Delete temporary files
                                     ▼
                               DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `parsing.pptx`
- `model.common`

## 5. External Libraries / APIs
- **Apache POI Scratchpad (`org.apache.poi.hslf.usermodel.*`)**: Library used to parse native binary PPT streams, slide structures, text runs, and OLE structures.
- **LibreOffice CLI (`libreoffice`)**: Headless utility used to convert PPT to PPTX in the fallback path.

## 6. Important Classes and Responsibilities
### `PPTParser`
- **Fallback Orchestration**: Catches parsing failures from POI, records the error state in `PPTParseResult`, and transparently routes execution to the fallback pipeline.

### `PPTExtractionValidator`
- **Quality Audits**: Ensures that the native parser successfully extracted at least one text run, image, or embedded object. If all three are zero, the validator triggers fallback.

### `PPTToPPTXConverter`
- **Subprocess Execution**: Builds and triggers `libreoffice --headless --convert-to pptx --outdir <temp-dir> <input-file>`.
