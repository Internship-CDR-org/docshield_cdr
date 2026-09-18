# Shared OOXML Threat Analysis (`threat.ooxml`)

## Overview

The `threat.ooxml` package implements shared capability-based security analysis for Open Packaging Conventions (OPC / OOXML) files, spanning **DOCX**, **PPTX**, and **XLSX**.

Because Microsoft Word, PowerPoint, and Excel share the same underlying ZIP packaging, XML relationship mapping, Content-Types declarations, and OLE embedding structures, `OOXMLThreatAnalyzer` and `OLEAnalyzer` provide common, unified detection for all three formats.

---

## Key Classes & Capabilities

### 1. [`OOXMLThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java)
- **Path**: `src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java`
- **Responsibilities**:
  - **VBA Project Detection**: Detects `vbaProject.bin`, `vbaProjectSignature.bin`, and `vbaData.xml` part names and relationships.
  - **ActiveX Controls**: Identifies `activeX` and `ctrlProps` part paths, content types (`application/vnd.ms-office.activeX+xml`), and control relationships.
  - **Excel Macro Sheets**: Flags `xl/macrosheets/` and macro-sheet content types.
  - **External Connections & Queries**: Detects `xl/connections.xml`, `xl/externallinks/`, and `xl/querytables/`.
  - **Embedded Objects & Packages**: Identifies `/embeddings/` storage and `oleObject` content types. (Treated as `OBSERVATION` until deeper inspection).
  - **SVG Security**: Scans SVG resources for `<script>`, event handlers (`onload=`, `onclick=`), JavaScript/VBScript URIs, `<foreignObject>`, and external URI references (`href=`, `src=`).
  - **XML Declarations**: Flags forbidden `<!DOCTYPE` and `<!ENTITY` constructs.
  - **DDE/DDEAUTO**: Detects DDE execution instructions in Word XML fields and Excel `<f>` formulas.
  - **Word External Fields**: Flags `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, and `IMPORT`.
  - **PowerPoint Actions**: Identifies `ppaction://program`, `ppaction://macro`, `ppaction://ole`, `runprogram`, `runmacro`, and `oleverb`.
  - **Relationship Validation**: Checks all `r:id`, `r:embed`, `r:link` XML attributes against the part's `.rels` relationship table; flags dangling references as `SUSPICIOUS` `INVALID_RELATIONSHIP`. Validates local relationship targets against physical parts; flags dangling local targets as `MISSING_TARGET`.
  - **Dangerous URI Schemes**: Flags `file:`, `javascript:`, `vbscript:`, `data:`, `ms-`, `shell:`, `mk:`, `ms-appx:`, `ms-appdata:`, and `about:javascript`.
  - **Native Executable Signatures**: Validates embedded binaries for PE (`MZ` + valid `PE\0\0` at `e_lfanew` offset), ELF (`\x7fELF`), Mach-O (32-bit & 64-bit magic numbers), and script shebangs (`#!`).
  - **Package Path Traversal**: Rejects traversing part names (`..` segments).

---

### 2. [`OLEAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OLEAnalyzer.java)
- **Path**: `src/main/java/threat/ooxml/OLEAnalyzer.java`
- **Responsibilities**:
  - Validates OLE2 Compound Document magic signature (`\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1`).
  - Mounts OLE directory trees via Apache POI `POIFSFileSystem` with strict safety limits:
    - `MAX_STORAGE_DEPTH = 32` (defends against recursive storage bombs)
    - `MAX_ENTRIES = 4096` (defends against entry exhaustion)
    - `MAX_STREAM_BYTES = 64 MB` (defends against decompression memory exhaustion)
  - Identifies VBA macro streams (`vba`, `dir`, `_VBA_PROJECT`).
  - Structurally parses `\x01Ole10Native` stream records (label, filename, source command, payload size, and payload bytes).
  - Inspects extracted stream payloads for native signatures:
    - PE executable (requires `MZ` header AND 4-byte `PE\0\0` at DWORD `e_lfanew` offset `0x3C`).
    - ELF executable (`\x7fELF`).
    - Mach-O executable (`0xFEEDFACE`, `0xFEEDFACF`, `0xCEFAEDFE`, `0xCFFAEDFE`; Java class file `0xCAFEBABE` excluded).
    - EICAR antivirus test file marker (`eicar-standard-antivirus-test-file`).
    - Script interpreter keywords (`#!`, `powershell`, `wscript.shell`, `invoke-expression`).

---

## Threat Detection Coverage Table

| Threat / Capability | Detection Class | Evidence Checked | Classification & Severity | Blocking? | Sanitized? |
|---|---|---|---|---|---|
| **VBA Macro Project** | `OOXMLThreatAnalyzer` | `/vbaproject.bin`, `/vbaprojectsignature.bin`, `/vbadata.xml`, relationship type `.../relationships/vbaproject` | `THREAT` / `HIGH` | **YES** | **YES** (part + relationship + XML refs removed) |
| **ActiveX Control** | `OOXMLThreatAnalyzer` | `/activex/`, `/ctrlprops/`, ContentType `...activex...`, relationship type `.../activexcontrol`, `.../control` | `THREAT` / `HIGH` | **YES** | **YES** (control part + relationship removed) |
| **XLM Macro Sheet** | `OOXMLThreatAnalyzer` | `xl/macrosheets/`, ContentType `...macrosheet...` | `THREAT` / `CRITICAL` | **YES** | **YES** (part + relationships removed) |
| **External Connections / Queries** | `OOXMLThreatAnalyzer` | `xl/connections.xml`, `xl/externallinks/`, `xl/querytables/`, relationship types `connection`, `query`, `externallink` | `POLICY_VIOLATION` / `HIGH` or `THREAT` / `HIGH` | **YES** | **YES** (part + relationship removed) |
| **Embedded Object Boundary** | `OOXMLThreatAnalyzer` | `/embeddings/`, ContentType `...oleObject...`, `...embeddedPackage...` | `OBSERVATION` / `INFO` | **NO** (audited recursively) | **Preserved if safe; removed if unsafe** |
| **Malicious XML / XXE** | `OOXMLThreatAnalyzer` | `<!DOCTYPE`, `<!ENTITY` in any XML part | `THREAT` / `HIGH` | **YES** | **YES** (DTD & entity declarations stripped) |
| **DDE / DDEAUTO** | `OOXMLThreatAnalyzer` | DDE tokens in Word field instructions or Excel formulas | `THREAT` / `CRITICAL` | **YES** | **YES** (instruction stripped, cached text preserved) |
| **Word External Fields** | `OOXMLThreatAnalyzer` | `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, `IMPORT` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (field instruction stripped) |
| **PPTX Action Execution** | `OOXMLThreatAnalyzer` | `ppaction://program`, `ppaction://macro`, `ppaction://ole`, `action="runprogram"` | `THREAT` / `CRITICAL` | **YES** | **YES** (action element + relationship removed) |
| **Dangling Relationship Reference** | `OOXMLThreatAnalyzer` | `r:id`, `r:embed`, `r:link` with no matching `.rels` entry | `SUSPICIOUS` / `HIGH` | **YES** | **YES** (attribute / element stripped) |
| **Missing Relationship Target** | `OOXMLThreatAnalyzer` | Internal relationship targeting non-existent package part | `SUSPICIOUS` / `HIGH` | **YES** | **YES** (relationship + references removed) |
| **Dangerous External URI** | `OOXMLThreatAnalyzer` | `file:`, `javascript:`, `vbscript:`, `data:`, `ms-`, `shell:`, `mk:`, `ms-appx:` | `THREAT` / `CRITICAL` | **YES** | **YES** (relationship removed) |
| **External Template** | `OOXMLThreatAnalyzer` | Relationship type `.../attachedTemplate`, `.../template` | `THREAT` / `HIGH` | **YES** | **YES** (relationship removed) |
| **Active / Malicious SVG** | `OOXMLThreatAnalyzer` | `<script>`, `onload=`, `javascript:`, `<foreignObject>`, external `src=` in SVG parts | `THREAT` / `HIGH` | **YES** | **YES** (part + references removed) |
| **Package Path Traversal** | `OOXMLThreatAnalyzer` | Part name containing `/..`, `../`, `..\`, leading `/` | `THREAT` / `CRITICAL` | **YES** | **YES** (part removed / rejected) |
| **Executable Embedded Payload** | `OOXMLThreatAnalyzer` | Executable extension (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, etc.) or PE/ELF/Mach-O magic in part data | `THREAT` / `CRITICAL` | **YES** | **YES** (part + references removed) |
| **OLE Storage Nesting Bomb** | `OLEAnalyzer` | Directory nesting depth > 32 | `SUSPICIOUS` / `CRITICAL` | **YES** | **YES** (containing OLE object removed) |
| **OLE Entry Count Bomb** | `OLEAnalyzer` | Compound file entry count > 4096 | `SUSPICIOUS` / `CRITICAL` | **YES** | **YES** (containing OLE object removed) |
| **OLE VBA Stream** | `OLEAnalyzer` | OLE stream named `vba`, `dir`, `_vba_project` | `THREAT` / `CRITICAL` | **YES** | **YES** (containing OLE object removed) |
| **Ole10Native Executable** | `OLEAnalyzer` | Valid PE/ELF/Mach-O/EICAR/script signature in Ole10Native payload | `THREAT` / `CRITICAL` | **YES** | **YES** (containing OLE object removed) |
| **Ordinary External Hyperlink** | `OOXMLThreatAnalyzer` | Valid external HTTP/HTTPS URI | `OBSERVATION` / `INFO` | **NO** | **Preserved unchanged** |
