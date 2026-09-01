# XLSX Sanitization Subsystem (`sanitization.xlsx`)

This package contains sanitizers that disarm security threats inside XLSX Excel spreadsheet files.

## 1. Purpose
The purpose of the `sanitization.xlsx` directory is to execute disarming policies on spreadsheet document packages (`OOXMLPackage`). It processes findings produced by XLSX analyzers and removes active content elements (VBA macro project files and ActiveX controls) along with their relationship links.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `XLSXThreatSanitizer.java` | Scans findings list for `VBA_PROJECT` and `ACTIVEX_OBJECT` threats, removing their matching package parts and incoming relationship mappings. | `XLSXThreatSanitizer` |

## 3. How the Directory Fits into DocShield
- `XLSXCDRProcessor` invokes `XLSXThreatSanitizer.sanitize(packageData, findings)` before writing the reconstructed workbook.
- The sanitizer removes components from the `OOXMLPackage` in-place.

```
       OOXMLPackage + Security Findings
                  │
                  ▼
         XLSXThreatSanitizer
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
  - `VBA_PROJECT`: Removes the macro file part (`xl/vbaproject.bin`) and its relationship from the presentation catalog.
  - `ACTIVEX_OBJECT`: Removes control definition parts (`xl/activex/activeX*.xml`, `xl/activex/activeX*.bin`) and their relationships.
- **Relational Integrity Preservation**: Removing relationship definitions ensures that Excel will not display warnings about missing macros or active elements upon opening the sanitized spreadsheet.
