# src/main/java Directory

This is the root source directory for the Java codebase of DocShield, containing the application entry point and coordinating the document identification, parsing, disarming, reconstruction, and reporting flows.

## 1. Purpose
The purpose of this directory is to house the primary coordinator class, `Main`, which serves as the CLI driver for DocShield. It binds all other subsystems (identification, parsing, processing, reporting) together.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `Main.java` | Application entry point. Reads CLI arguments, executes the file identification logic, triggers the format-specific parser, determines the appropriate CDR processor, runs the processor, and invokes reporting. | `Main` |

## 3. How the Directory Fits into DocShield
`Main` acts as the orchestrator of the entire process. It accepts input and output file paths from the CLI arguments, detects the format, builds the internal document model representation, triggers threat inspection and disarming, writes the reconstructed output file, and finally generates a threat report.

```
                  CLI Input (run.sh)
                           │
                           ▼
                       Main.java
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
FileIdentifier      ParserFactory        CDRProcessor
 (Format & ID)      (Get Parser)      (DOCX/PPTX/XLSX)
        │                  │                  │
        │                  ▼                  ▼
        │            DocumentModel      Reconstruction & Sanitization
        │                  │                  │
        └─────────────────┬┴──────────────────┘
                          ▼
                     ReportWriter
                          │
                          ▼
                     CDR Report & Output
```

## 4. Dependencies
- `identification`
- `model.common`
- `parsing.common`
- `processing.common`
- `processing.docx`
- `processing.pptx`
- `processing.xlsx`
- `reporting`

## 5. External Libraries / APIs
None directly in `Main.java`. Uses standard JDK APIs (`java.nio.file.Path`).

## 6. Important Classes and Responsibilities
### `Main`
- **Orchestration**: Manages the flow of the engine from input file to disarmed output file.
- **Validation Fallback**: Triggers basic `DOCExtractionValidator` if the document is legacy Word format (`DOC`).
- **Reporting Routing**: Passes the parsed `DocumentModel` and `CDRResult` to the `ReportWriter` to generate output reports.

## 7. Important Design Decisions
- **Unified Pipeline**: Implements a standard detection -> parse -> process -> report sequence.
- **Factory Resolution**: Dynamically retrieves parsers using the `ParserFactory` pattern, separating format-specific parser knowledge from the core driver.

## 8. Reconstruction Behavior
For non-OOXML formats (like PDF, RTF, DOC, PPT, XLS), `Main` executes only parsing and reporting, leaving the input file unmodified and writing a report, as reconstruction is only implemented via `CDRProcessor` for modern OOXML formats (`DOCX`, `PPTX`, `XLSX`).

## 9. Example Usage
```bash
./run.sh input.pptx output.pptx
```
This script builds the classpath and executes `Main` with the provided arguments.
