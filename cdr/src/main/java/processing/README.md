# CDR Processing Subsystem (`processing`)

This parent directory contains classes responsible for driving the Content Disarm and Reconstruction (CDR) process on documents.

## 1. Purpose
The purpose of the `processing` directory is to define the workflow orchestration for disarming and reconstructing packages. Subdirectories contain format-specific processors that sequence threat detection, object sanitization, file reconstruction, and post-reconstruction integrity validation.

## 2. Directory Structure and Responsibilities
| Subdirectory | Responsibility |
| :--- | :--- |
| [`common`](file:///d:/CAIR%20DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/README.md) | Defines the main `CDRProcessor` interface and `CDRResult` state container. |
| [`docx`](file:///d:/CAIR%20DOC%20SHIELD/DocShield/cdr/src/main/java/processing/docx/README.md) | Coordinates the CDR flow for DOCX Word documents. |
| [`pptx`](file:///d:/CAIR%20DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pptx/README.md) | Coordinates the CDR flow for PPTX PowerPoint presentations. |
| [`xlsx`](file:///d:/CAIR%20DOC%20SHIELD/DocShield/cdr/src/main/java/processing/xlsx/README.md) | Coordinates the CDR flow for XLSX Excel spreadsheets. |

## 3. How the Directory Fits into DocShield
- `Main` delegates the execution of disarming to a format-specific `CDRProcessor` retrieved based on the file format.
- The processor returns a `CDRResult` which is used to output a summary to the console and write the final disarming report.

```
       Main.java
          │
          ▼ (Invokes process())
     CDRProcessor (e.g., DOCXCDRProcessor)
          │
          ├─► Parse zip package into memory representation
          ├─► Run Threat Analyzer (find vulnerabilities)
          ├─► Run Threat Sanitizer (strip threats)
          ├─► Run Reconstruction Writer (write new package)
          └─► Run Integrity Validator (verify zip structure)
          │
          ▼ (Returns)
      CDRResult ──► ReportWriter (Writes CDR Report)
```

## 4. Dependencies
- `threat.common`
- `sanitization` (format-specific)
- `reconstruction`
- `validation`
