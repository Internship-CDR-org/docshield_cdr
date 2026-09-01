# DOCX Sanitization Subsystem (`sanitization.docx`)

This package contains sanitizers that disarm security threats inside DOCX documents.

## 1. Purpose
The purpose of the `sanitization.docx` directory is to execute disarming policies on Word document packages (`OOXMLPackage`). It processes findings produced by DOCX analyzers and removes active content elements (VBA macro project files and ActiveX objects) along with their relationships to ensure MS Word does not execute active content when opening the reconstructed output.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DOCXThreatSanitizer.java` | Scans findings for `VBA_PROJECT` and `ACTIVEX_OBJECT` threats, removing their matching package parts and incoming relationship links. | `DOCXThreatSanitizer` |

## 3. How the Directory Fits into DocShield
- `DOCXCDRProcessor` invokes `DOCXThreatSanitizer.sanitize(packageData, findings)` before writing the reconstructed document.
- The sanitizer removes components from the `OOXMLPackage` in-place.

```
       OOXMLPackage + Security Findings
                  │
                  ▼
         DOCXThreatSanitizer
          ├─► Identifies findings of type VBA_PROJECT and ACTIVEX_OBJECT
          ├─► Removes incoming relationship mapping in source parts
          └─► Removes the raw active content part (e.g. vbaproject.bin) from package
                  │
                  ▼
         Sanitized OOXMLPackage
```

## 4. Dependencies
- `model.ooxml`
- `threat.common`

## 5. Security Considerations
- **Stripped Threats**:
  - `VBA_PROJECT`: Removes the macro file part (`word/vbaproject.bin`) and its relationship from the presentation catalog.
  - `ACTIVEX_OBJECT`: Removes control definition parts (`word/activex/activeX*.xml`, `word/activex/activeX*.bin`) and their relationships.
- **Dangling References Prevention**: Removing the relationship entries ensures that Microsoft Word will not try to resolve or search for the deleted ActiveX components or macro definitions.
