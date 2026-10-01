# Modern XLSX Parser Subsystem (`parsing.xlsx`)

This package is responsible for parsing modern Microsoft Excel Open XML Spreadsheet formats (`.xlsx` files).

## 1. Purpose
The purpose of the `parsing.xlsx` directory is to parse modern spreadsheet documents, extracting text cell values and mapping cell addresses to populate the intermediate `DocumentModel`.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `XLSXParser.java` | Core driver class. Resolves XLSX content parsing and fills the document model structure. | `XLSXParser` |
| `XLSXContentParser.java` | Custom XML parser that scans the ZIP package for spreadsheet data and maps cell values. | `XLSXContentParser` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` returns `XLSXParser` when processing `.xlsx` spreadsheet files.
- The parser invokes `XLSXContentParser` to loop through worksheets and register cell contents inside the unified `DocumentModel`.

```
                  Input XLSX File
                         │
                         ▼
                    XLSXParser
                         │
                         ▼
                 XLSXContentParser
                  ├─► Reads xl/sharedStrings.xml
                  └─► Iterates xl/worksheets/sheet*.xml (Parses cell tags <c> & values <v>)
                         │
                         ▼
                   DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `model.common`

## 5. External Libraries / APIs
- **Java XML DOM APIs (`javax.xml.parsers.DocumentBuilderFactory`)**: Used to read cell elements (`<c>`), reference attributes (`r`), type attributes (`t`), and string elements (`<si>`, `<t>`).
- **Java ZIP APIs (`java.util.zip.ZipFile`, `java.util.zip.ZipEntry`)**: Used to decompress the individual worksheet XML structures.

## 6. Important Design Decisions
- **Manual XML Parsing (No Apache POI Dependency)**: Unlike other parsers in DocShield, `XLSXContentParser` does not use the Apache POI library. Instead, it reads the spreadsheet files directly using `ZipFile` and XML DOM parsing. It parses the shared string dictionary (`xl/sharedStrings.xml`) and translates indexed cell references (`t="s"`) manually. This keeps memory usage low for large spreadsheet datasets.
- **Lightweight Cell Extraction**: Only cell values and cell references (e.g. `Cell A1 = Value`) are extracted, leaving structural metadata (styling, row heights, and sheet configurations) to be processed at the package level during CDR.
