# Legacy XLS Parser Subsystem (`parsing.xls`)

This package is responsible for parsing legacy Microsoft Excel binary spreadsheet formats (`.xls` files).

## 1. Purpose
The purpose of the `parsing.xls` directory is to extract spreadsheet cell values, sheet structures, metadata properties, graphics, hyperlinks, and embedded object attachments from legacy `.xls` files. It utilizes a dual-path design: attempting native POI HSSF parsing first, and falling back to headless LibreOffice conversion to XLSX if native parsing fails or is empty.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `XLSParser.java` | Main driver class. Manages native HSSF parsing, result validation, and fallback conversion. | `XLSParser` |
| `XLSContentParser.java` | Extracts cell values, sheets, coordinates, and cell addresses. | `XLSContentParser`, `CellData` |
| `XLSMetadataParser.java` | Extracts OLE SummaryInformation metadata properties. | `XLSMetadataParser` |
| `XLSResourceParser.java` | Extracts graphics (pictures) and embedded OLE attachments. | `XLSResourceParser` |
| `XLSHyperlinkExtractor.java` | Extracts hyperlinks embedded in sheets and cells. | `XLSHyperlinkExtractor` |
| `XLSStructureParser.java` | Inspects workbook streams to map sheets count and properties. | `XLSStructureParser` |
| `XLSParseResult.java` | Holds parsing statistics and fallback conversion state. | `XLSParseResult` |
| `XLSExtractionValidator.java` | Validates if native HSSF parsing extracted cells, images, or objects. | `XLSExtractionValidator` |
| `XLSToXLSXConverter.java` | Spawns headless LibreOffice to convert XLS into modern XLSX. | `XLSToXLSXConverter` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` resolves the `XLSParser` when processing a `.xls` file.
- The parser tries native HSSF path.
- If HSSF fails or is validated as empty by `XLSExtractionValidator`, `XLSParser` invokes `XLSToXLSXConverter` to generate a temporary XLSX file.
- It then processes the converted file using `XLSXParser` and deletes the temporary file afterwards.

```
                   Input XLS File
                         │
                         ▼
                     XLSParser
                         │
             ┌───────────┴───────────┐
             ▼ (Native Path)         │
       parseUsingHSSF                │
             │                       │
             ▼                       ▼ (Fallback Path on Failure/Empty)
    XLSExtractionValidator ──────► parseUsingXLSXFallback
      (Check cell/image/obj)         │
             │                       ├─► XLSToXLSXConverter (LibreOffice CLI)
             ▼ (Pass)                ├─► XLSXParser (Parses temporary XLSX)
        DocumentModel                ├─► Delete temporary files
                                     ▼
                               DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `parsing.xlsx`
- `model.common`

## 5. External Libraries / APIs
- **Apache POI (`org.apache.poi.hssf.usermodel.*`)**: Library used to parse native binary XLS streams, HSSF workbooks, rows, cells, and drawings.
- **LibreOffice CLI (`libreoffice`)**: Headless utility used to convert XLS to XLSX in the fallback path.

## 6. Important Classes and Responsibilities
### `XLSParser`
- **Fallback Execution**: Catches parsing failures from POI HSSF, logs the failure in `XLSParseResult`, and transparently routes to the fallback path.

### `XLSExtractionValidator`
- **Quality Checks**: Checks that the native parser successfully extracted at least one cell value, image, or embedded object. If all three are zero, the validator triggers fallback.

### `XLSToXLSXConverter`
- **Subprocess Execution**: Builds and triggers `libreoffice --headless --convert-to xlsx --outdir <temp-dir> <input-file>`.
