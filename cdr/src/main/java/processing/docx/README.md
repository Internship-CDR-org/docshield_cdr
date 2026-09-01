# DOCX Processing Subsystem (`processing.docx`)

This package is responsible for driving the Content Disarm and Reconstruction process for DOCX documents.

## 1. Purpose
The purpose of the `processing.docx` directory is to coordinate the complete CDR pipeline for modern Word processing files (`.docx`). It reads the input document package, invokes analysis, executes sanitization actions, serializes the disarmed package, and validates structural integrity.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DOCXCDRProcessor.java` | Main class implementing the `CDRProcessor` interface. Coordinates package loading, analyzing, sanitizing, reconstructing, and validating for DOCX files. | `DOCXCDRProcessor` |

## 3. How the Directory Fits into DocShield
- `Main` invokes `DOCXCDRProcessor` when the detected format is `DOCX`.
- The processor coordinates the sequential pipeline phases:

```
  Input DOCX Path ──► [OOXMLPackageReader] ──► OOXMLPackage
                                                  │
                                                  ▼
                                          [DOCXThreatAnalyzer] (Finds threats)
                                                  │
                                                  ▼
                                          [DOCXThreatSanitizer] (Strips findings)
                                                  │
                                                  ▼
  Output DOCX Path ◄── [OOXMLIntegrityValidator] ◄── [OOXMLPackageWriter]
```

## 4. Dependencies
- `model.ooxml`
- `parsing.ooxml`
- `reconstruction`
- `sanitization.docx`
- `threat.common`
- `threat.docx`
- `processing.common`
- `validation.ooxml`

## 5. External Libraries / APIs
None directly. Delegates to underlying parsers and writers which use JDK ZIP APIs and XML DOM parsers.

## 6. Important Classes and Responsibilities
### `DOCXCDRProcessor`
- **Reconstruction Verification**: Confirms that the reconstructed output file exists and has a size greater than 0.
- **Integrity Validation**: Re-reads the generated output file and validates the namespace paths using `OOXMLIntegrityValidator` to prevent outputting corrupted documents.
- **Active Content Check**: Inspects the output file to confirm that macros and ActiveX components (`word/vbaproject.bin`, `word/activex/*`) have been successfully removed if threats were identified.
