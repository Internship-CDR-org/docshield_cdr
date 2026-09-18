# PPTX Threat Analysis (`threat.pptx`)

## Overview

The `threat.pptx` package provides PowerPoint-specific security analysis layered on top of `OOXMLThreatAnalyzer` and `OLEAnalyzer`.

PowerPoint presentations can carry active execution vectors via PresentationML interactive slide actions (`hlinkClick`, `hlinkHover`), control persistence records (`ppt/ctrlprops/`), embedded OLE native payloads, and active SVG vector images.

---

## Key Classes & Architecture

### 1. [`PPTXThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/PPTXThreatAnalyzer.java)
- **Path**: `src/main/java/threat/pptx/PPTXThreatAnalyzer.java`
- **Responsibilities**:
  - Runs [`OOXMLThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java) for package-wide threats.
  - Runs [`OLEAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/OLEAnalyzer.java) for nested Compound Document payloads.
  - Inspects `ppt/ctrlprops/` for ActiveX control persistence data.

### 2. Supporting PPTX Analyzers & Payload Tools
- **[`Ole10NativeAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/Ole10NativeAnalyzer.java)**: Parses OLE `Ole10Native` binary records to extract filename, execution command, and embedded file bytes.
- **[`PayloadIdentifier`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/PayloadIdentifier.java)**: Identifies payload format from byte content headers (`MZ`, `\x7fELF`, `%PDF-`, `PK\x03\x04`, script keywords) and file extensions (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.pdf`, `.svg`).
- **[`PayloadFingerprint`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/PayloadFingerprint.java)**: Computes SHA-256 digests of extracted embedded payloads.
- **[`SVGAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/SVGAnalyzer.java)**: Inspects SVG parts for `<script>`, event handlers (`onload`, `onclick`), external resources, and script URIs.
- **[`EmbeddedObjectAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/EmbeddedObjectAnalyzer.java)**: Evaluates embedded package objects.
- **[`RelationshipAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/RelationshipAnalyzer.java)**: Audits PPTX-specific relationship targets and types.

---

## Threat Detection Coverage Table

| Threat / Capability | Detection Class | Evidence Checked | Classification & Severity | Blocking? | Sanitized? |
|---|---|---|---|---|---|
| **PowerPoint Program Action** | `OOXMLThreatAnalyzer` | `ppaction://program`, `action="runprogram"` in slide XML | `THREAT` / `CRITICAL` | **YES** | **YES** (action element + relationship removed) |
| **PowerPoint Macro Action** | `OOXMLThreatAnalyzer` | `ppaction://macro`, `action="runmacro"` in slide XML | `THREAT` / `CRITICAL` | **YES** | **YES** (action element + relationship removed) |
| **PowerPoint OLE Verb Action** | `OOXMLThreatAnalyzer` | `ppaction://ole`, `action="oleverb"` in slide XML | `THREAT` / `CRITICAL` | **YES** | **YES** (action element + relationship removed) |
| **ActiveX Control Persistence** | `PPTXThreatAnalyzer` | `ppt/ctrlprops/` part path | `THREAT` / `HIGH` | **YES** | **YES** (ctrlProps part + relationships removed) |
| **Active / Script-Bearing SVG** | `OOXMLThreatAnalyzer` / `SVGAnalyzer` | `<script>`, event handlers (`onclick=`, etc.), `javascript:`, `<foreignObject>`, external `href=` | `THREAT` / `HIGH` | **YES** | **YES** (SVG part + relationship removed) |
| **External Presentation Media Rel** | `OOXMLThreatAnalyzer` | External relationship to slide, chart, model3d, or media | `THREAT` / `HIGH` | **YES** | **YES** (relationship removed) |
| **Ole10Native Executable Payload** | `OLEAnalyzer` / `Ole10NativeAnalyzer` | PE (`MZ` + `PE\0\0`), ELF, Mach-O, EICAR, or script signature in Ole10Native payload | `THREAT` / `CRITICAL` | **YES** | **YES** (containing OLE object removed) |
| **Benign Embedded OLE Document** | `OLEAnalyzer` | Valid OLE compound document with no active streams or executable signatures | `OBSERVATION` / `INFO` | **NO** | **Preserved after recursive safety verification** |
