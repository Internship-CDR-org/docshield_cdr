# Reporting Subsystem (`reporting`)

This package is responsible for formatting and writing execution analysis reports for processed files.

## 1. Purpose
The purpose of the `reporting` directory is to compile the extracted document features, identified security findings, disarming actions, and reconstruction logs into a human-readable text report (`output/reports/<filename>_CDR_Report.txt`).

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `ReportWriter.java` | Builds the text layout and writes out formatted metadata, IR text components, images, embedded elements, structures, links, threat classifications, and disarming outcomes. | `ReportWriter` |

## 3. How the Directory Fits into DocShield
- `Main` invokes `ReportWriter.write(model, inputFile, result)` after processing completes.
- The writer creates the report inside the `output/reports/` folder.

```
  DocumentModel (Parsed features)
                │
                ├─► [ReportWriter] ──► Text File: output/reports/<filename>_CDR_Report.txt
                │
  CDRResult (Findings & actions)
```

## 4. Dependencies
- `model.common`
- `processing.common` (holds `CDRResult`)
- `threat.common` (holds `SecurityFinding` models)

## 5. External Libraries / APIs
None. Standard JDK libraries only (`java.io.BufferedWriter`, `java.nio.file.Files`, `java.nio.file.Path`).

## 6. Important Classes and Responsibilities
### `ReportWriter`
- **Output Directory Creation**: Ensures the folder path `output/reports` is created on the filesystem before attempting to save the file.
- **Section Generation**: Divides reports into logical sections:
  1. `FILE IDENTIFICATION`: Filename, size, MIME type, cryptographic hash.
  2. `METADATA`: Document title, author, editor metadata.
  3. `IR TEXT`: Extracted character blocks with styling fonts, sizes, page numbers, and page boundary positions.
  4. `IR IMAGES`: Image resources filenames, MIME types, and dimensions.
  5. `IR EMBEDDED OBJECTS`: Zipped binary payloads types and sizes.
  6. `IR STRUCTURE`: Slide counts, worksheet cell locations, layouts.
  7. `IR HYPERLINKS`: URLs and display descriptions.
  8. `IR THREATS`: Suspicions tagged within the document format.
  9. `SECURITY FINDINGS`: Classification details, severity levels, and evidence logs for matching rules.
  10. `SANITIZATION`: List of disarming actions executed by the sanitizers.
  11. `RECONSTRUCTION`: Serialization status and integrity validation logs.
