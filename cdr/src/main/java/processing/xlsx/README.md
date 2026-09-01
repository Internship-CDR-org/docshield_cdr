# XLSX Processing Subsystem (`processing.xlsx`)

This package is responsible for driving the Content Disarm and Reconstruction process for XLSX spreadsheet files.

## 1. Purpose
The purpose of the `processing.xlsx` directory is to coordinate the complete CDR pipeline for modern Excel files (`.xlsx`). It coordinates spreadsheet package loading, runs threat identification analysis, sanitizes active content, writes the disarmed workbook zip package, and verifies file integrity.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `XLSXCDRProcessor.java` | Main class implementing the `CDRProcessor` interface. Coordinates package reading, analyzing, sanitizing, reconstructing, and validating for XLSX spreadsheet files. | `XLSXCDRProcessor` |

## 3. How the Directory Fits into DocShield
- `Main` invokes `XLSXCDRProcessor` when the detected format is `XLSX`.
- The processor runs the standard package-level pipeline phases:

```
  Input XLSX Path ──► [OOXMLPackageReader] ──► OOXMLPackage
                                                  │
                                                  ▼
                                          [XLSXThreatAnalyzer] (Finds threats)
                                                  │
                                                  ▼
                                          [XLSXThreatSanitizer] (Strips findings)
                                                  │
                                                  ▼
  Output XLSX Path ◄── [OOXMLIntegrityValidator] ◄── [OOXMLPackageWriter]
```

## 4. Dependencies
- `model.ooxml`
- `parsing.ooxml`
- `reconstruction`
- `sanitization.xlsx`
- `threat.common`
- `threat.xlsx`
- `processing.common`
- `validation.ooxml`

## 5. External Libraries / APIs
None directly. Delegates to underlying components which use standard JDK ZIP APIs and XML DOM builders.

## 6. Important Classes and Responsibilities
### `XLSXCDRProcessor`
- **Reconstruction Verification**: Verifies the reconstructed spreadsheet exists on disk and is larger than 0 bytes.
- **Integrity Validation**: Re-reads the generated spreadsheet and validates its parts structure using `OOXMLIntegrityValidator`.
- **Active Content Check**: Audits the reconstructed XLSX file to confirm that macros and ActiveX components (`xl/vbaproject.bin`, `xl/activex/*`) have been successfully removed if threats were identified.
