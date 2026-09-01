# Common Processing Infrastructure (`processing.common`)

This package defines the standard interface and execution result types for the Content Disarm and Reconstruction pipeline.

## 1. Purpose
The purpose of the `processing.common` directory is to establish a uniform execution contract (`CDRProcessor`) and output container (`CDRResult`) for the DocShield CDR pipeline. This allows the system orchestrator (`Main`) to process different document formats using a consistent interface.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `CDRProcessor.java` | Interface defining the core `process()` method for disarming and reconstructing documents. | `CDRProcessor` (interface) |
| `CDRResult.java` | Standard result class containing findings, actions, output path, reconstruction success, integrity status, and threat counts. | `CDRResult` |

## 3. How the Directory Fits into DocShield
- `Main` holds references to `CDRProcessor` implementations (`DOCXCDRProcessor`, `PPTXCDRProcessor`, `XLSXCDRProcessor`).
- Running `process(input, output)` triggers format-specific analyzer, sanitizer, writer, and validator chains.
- The returned `CDRResult` is processed by `Main` to print a terminal summary and is saved to disk via `ReportWriter`.

```
                  Main.java
                      │
                      ▼ (Executes process())
              CDRProcessor (DOCX, PPTX, XLSX)
                      │
                      ▼ (Produces)
              CDRResult
                      │
                      ├─► Main.java (Prints CLI summary)
                      └─► ReportWriter (Generates CDR Report)
```

## 4. Dependencies
- `threat.common` (for `SecurityFinding` and `ThreatSeverity` mappings)

## 5. External Libraries / APIs
None. Standard JDK libraries only (`java.nio.file.Path`, `java.util.List`, etc.).

## 6. Important Classes and Responsibilities
### `CDRResult`
- **Findings Registry**: Holds a list of discovered `SecurityFinding` objects.
- **Actions Registry**: Tracks the changes made to the file (e.g. "Removed embedded object: word/embeddings/oleObject1.bin").
- **Highest Severity**: Scans registered findings and returns the highest severity classification (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Threat Summary**: Returns a comma-separated summary string listing all detected threat categories (e.g., "OLE_OBJECT, MACRO").
- **Status Flags**: Houses logical state flags representing pipeline stages:
  - `reconstructionSuccessful`: Confirms if the reconstructed ZIP structure was written.
  - `integrityPassed`: Confirms if the reconstructed file passed structural validation checks.
  - `threatsRemoved`: Confirms if sanitization successfully stripped all identified findings.
