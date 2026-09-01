# DOCX Threat Analysis Subsystem (`threat.docx`)

This package is responsible for auditing modern DOCX document packages for active content security threats.

## 1. Purpose
The purpose of the `threat.docx` directory is to inspect modern Word documents (`OOXMLPackage`) for potential threats. It scans the package parts for active scripting files (VBA macros) and embedded interactive elements (ActiveX controls), logging observations as `SecurityFinding` records.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DOCXThreatAnalyzer.java` | Inspects package entries for VBA macro projects and ActiveX controls, mapping their relationship links. | `DOCXThreatAnalyzer` |

## 3. How the Directory Fits into DocShield
- `DOCXCDRProcessor` runs `DOCXThreatAnalyzer` on the parsed `OOXMLPackage`.
- The returned findings list is passed to `DOCXThreatSanitizer` to strip threats.

```
       Parsed OOXMLPackage
                │
                ▼ (Scanned by)
       DOCXThreatAnalyzer.analyze()
                │
                ▼ (Produces)
       List<SecurityFinding> (VBA_PROJECT, ACTIVEX_OBJECT)
                │
                ▼
       DOCXThreatSanitizer
```

## 4. Dependencies
- `model.ooxml`
- `threat.common`

## 5. Security Considerations
- **Detections Implemented**:
  - **VBA Macro Projects (`ThreatType.VBA_PROJECT`)**: Flags the presence of `word/vbaproject.bin` (embedded binary carrying macros). Severity: **HIGH**.
  - **ActiveX Controls (`ThreatType.ACTIVEX_OBJECT`)**: Flags package parts located under the path prefix `word/activex/` (interactive active controls). Severity: **HIGH**.
- **Evidence Gathering**: Logs target part size, location, and references.
- **Relational Path Tracking**: Resolves relative targets (such as `../activex/activeX1.xml` relative to `word/document.xml` to `word/activex/activeX1.xml`) using `resolveTarget()` to locate matching relationship nodes and identify the source part and relationship ID.
