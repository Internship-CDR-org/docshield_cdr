# DocShield Content Disarm & Reconstruction (CDR) Engine

DocShield is a high-performance Content Disarm and Reconstruction (CDR) engine built in Java. It safely identifies, parses, analyzes, sanitizes, and reconstructs document files to neutralize active content threats (such as macros, ActiveX controls, executable scripts, and malicious embedded payloads) before they reach users.

## 1. Project Purpose
DocShield provides a security pipeline that intercepts incoming files, audits them for vulnerabilities, and outputs clean versions with active threats disarmed while preserving the original styling, layout, and visual fidelity of non-malicious components.

## 2. Supported Formats
The engine supports the following document formats:
- **Modern Open XML (OOXML)**: Word (`DOCX`), PowerPoint (`PPTX`), Excel (`XLSX`).
- **Legacy Microsoft Office (OLE)**: Word (`DOC`), PowerPoint (`PPT`), Excel (`XLS`).
- **Standard Document Formats**: Portable Document Format (`PDF`), Rich Text Format (`RTF`).

## 3. Core Architecture Overview
DocShield uses a modular pipeline organized as follows:

```
  Input File
      │
      ▼
┌──────────────┐
│Identification│ magic bytes & zip structures analysis (Anti-Spoofing)
└──────┬───────┘
       │
       ▼
┌──────┴───────┐
│   Parsing    │ converts files into in-memory object models
└──────┬───────┘ (Native POI/PDFBox/Custom scanners or Headless LibreOffice converter fallbacks)
       │
       ▼
┌──────┴───────┐
│CDR Processing│ orchestrates analysis, sanitization, writing, and validation
└──────┬───────┘
       │
       ├─► [Threat Analysis]  Inspects components, scripts, SVG XXE, and OLE storage streams
       ├─► [Sanitization]     Deletes threat parts and clears relationship link maps
       ├─► [Reconstruction]   Writes sanitized parts and dynamically rebuilds .rels XML structures
       └─► [Validation]       Audits reconstructed zip structures and ensures target resolution
       │
       ▼
┌──────┴───────┐
│  Reporting   │ writes formatted run logs to output/reports/
└──────────────┘
```

## 4. Current Reconstruction Capabilities
- **OOXML Reconstruction (DOCX, PPTX, XLSX)**: One shared `OOXMLPackage` + `OOXMLPackageWriter` path. Physical parts and relationships are preserved generically; `.rels` files and `[Content_Types].xml` are regenerated from the sanitized package model.
- **Legacy office files (DOC, PPT, XLS)**: Reconstructed by converting the legacy binary formats to modern OOXML formats (DOCX, PPTX, XLSX) via a headless LibreOffice converter fallback, which are then processed and written out as sanitized OOXML files.
- **PDF & RTF**: Parsing and threat analysis are fully implemented. Extracted features and detected threat warnings are written to the CDR analysis report, but no reconstructed file is generated.

## 5. Threat Detection & Sanitization Capabilities
- **VBA Macro Disarming**: Detects macro projects (`vbaproject.bin`) inside DOCX, XLSX, and legacy OLE files. Sanitization deletes the macro files and removes all associated relationship references.
- **ActiveX Disarming**: Scans for ActiveX interactive controls (e.g. `word/activex/` or `xl/activex/` directories). Strips the parts and relationship entries.
- **Embedded OLE Payload Analysis**: Recursively mounts embedded OLE Compound Document directories, locates nested native attachments (`Ole10Native` streams), runs file signature audits, cryptographically hashes payloads (SHA-256), and blocks script/executable content (e.g. Batch, CMD, PowerShell, JS, VBS, PE, ELF).
- **SVG Active Content Checking**: Scans SVG vector drawings for script tags (`<script>`), event triggers (e.g. `onclick=`, `onload=`), JavaScript URIs, and external entities (XXE vulnerability vectors).
- **Relationship / External Content Analysis**: The common OOXML analyzer evaluates external relationships, dangerous URI schemes, external templates, external data connections, and package-target integrity.

## 6. Directory Structure
```
cdr/
├── pom.xml                               # Maven project configuration
├── run.sh                                # CLI run driver script
├── src/
│   ├── main/java/
│   │   ├── Main.java                     # Application entry point
│   │   ├── identification/               # Magic signature format detection
│   │   ├── model/
│   │   │   ├── common/                   # Format-independent IR models
│   │   │   ├── ooxml/                    # Generic OOXML package parts representation
│   │   │   └── pptx/                     # PPTX-only semantic models (layout/theme), not package storage
│   │   ├── parsing/
│   │   │   ├── common/                   # Parser factory & core/app metadata extractors
│   │   │   ├── doc/, docx/, pdf/, ppt/, pptx/, rtf/, xls/, xlsx/ # Format-specific parsers
│   │   │   └── ooxml/                    # Decompresses OOXML ZIP parts securely
│   │   ├── processing/
│   │   │   ├── common/                   # CDR processor contract & result container
│   │   │   └── docx/, pptx/, xlsx/       # Workflow pipeline orchestrators
│   │   ├── reconstruction/               # Shared OOXML package reconstruction
│   │   ├── reporting/                    # Writes formatted reports to output/reports/
│   │   ├── sanitization/
│   │   │   ├── common/                    # Shared OOXML sanitizer contract + implementation
│   │   │   └── docx/, pptx/, xlsx/        # Thin format entry points
│   │   ├── threat/
│   │   │   ├── common/                   # Common findings, categories, severities, analyzer contract
│   │   │   ├── ooxml/                    # Shared structural threat analyzer for DOCX/PPTX/XLSX
│   │   │   └── docx/, pptx/, xlsx/       # Format-specific/legacy analyzers where required
│   │   └── validation/
│   │       └── ooxml/                    # Post-reconstruction integrity validation checks
│   └── test/java/                        # Test suite (Unit, Round-trip, and Integrity tests)
└── output/                               # Generated reports and disarmed output files
```

## 7. Build Instructions
### Prerequisites
- **Java Development Kit (JDK)**: Version 21 or higher.
- **Apache Maven**: Version 3.x.

### Compilation
To compile the source files and package resources:
```bash
mvn clean compile
```

## 8. Run Instructions
To run the disarming engine:
```bash
./run.sh <input-file> <output-file>
```
*Note: Headless LibreOffice (`libreoffice` binary) must be installed and available in the system PATH if processing legacy Microsoft Office formats (DOC, PPT, XLS) to enable fallback conversion.*

## 9. Testing Instructions
To run unit and round-trip integration tests:
```bash
mvn test
```

## 10. Output Directories
- **Sanitized Documents**: Written directly to the `<output-file>` path specified in the run command.
- **CDR Reports**: Saved to `output/reports/<filename>_CDR_Report.txt`.

## 11. Known Limitations & Implementation Status
- **Reconstruction Constraints**: Direct reconstruction is only implemented for DOCX, PPTX, and XLSX formats. PDF and RTF documents are parsed for threat reporting only.
- **LibreOffice Dependency**: Legacy format processing (DOC, PPT, XLS) depends on the system having an external `libreoffice` binary in the PATH for fallback conversion. Fallback parsing will fail if LibreOffice is not installed.
- **Security coverage is capability-based and incremental**: the common OOXML layer covers structural active-content and external-resource classes; format-specific attack surfaces continue to be added under the same common threat/sanitization contracts. Unknown vulnerabilities cannot be guaranteed by signature matching alone.
