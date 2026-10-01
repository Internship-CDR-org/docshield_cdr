# DOCX Threat Analysis (`threat.docx`)

## Overview

The `threat.docx` package provides Word-specific security analysis layered on top of the shared `OOXMLThreatAnalyzer` and `OLEAnalyzer`.

Microsoft Word documents can carry active capabilities inside document XML fields (`w:instrText`, `w:fldSimple`), settings (`word/settings.xml`), alternative format chunks (`altChunk`), attached templates, and mail merge configurations that cannot be detected by package-level relationship scanning alone.

---

## Key Classes & Architecture

### [`DOCXThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/docx/DOCXThreatAnalyzer.java)
- **Path**: `src/main/java/threat/docx/DOCXThreatAnalyzer.java`
- **Delegation Flow**:
  1. Executes [`OOXMLThreatAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java) for common package-level threats (VBA, ActiveX, dangerous URIs, malicious XML, dangling relationships).
  2. Executes [`OLEAnalyzer`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/OLEAnalyzer.java) for embedded OLE Compound Document payloads.
  3. Inspects Word-specific XML parts (`word/document.xml`, `word/settings.xml`, `word/header*.xml`, `word/footer*.xml`, etc.).
  4. Inspects Word-specific package relationships.

---

## Threat Detection Coverage Table

| Threat / Capability | Detection Class | Evidence Checked | Classification & Severity | Blocking? | Sanitized? |
|---|---|---|---|---|---|
| **DDE / DDEAUTO Field Code** | `DOCXThreatAnalyzer` | `DDE`, `DDEAUTO` token inside `w:instrText` (including fragmented runs) or `w:fldSimple` | `THREAT` / `CRITICAL` | **YES** | **YES** (field instruction stripped; cached text preserved) |
| **MACROBUTTON Field Code** | `DOCXThreatAnalyzer` | `MACROBUTTON` token inside Word field instruction | `THREAT` / `CRITICAL` | **YES** | **YES** (field instruction stripped; visible text preserved) |
| **Dangerous URI in HYPERLINK Field** | `DOCXThreatAnalyzer` | `HYPERLINK` field referencing `file:`, `javascript:`, `vbscript:`, `data:`, `ms-`, `shell:`, `mk:` | `THREAT` / `CRITICAL` | **YES** | **YES** (field instruction stripped; display text preserved) |
| **Word External Content Fields** | `DOCXThreatAnalyzer` | `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, `IMPORT` tokens in field instructions | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (instruction stripped; cached display content preserved) |
| **Automatic Field Update Setting** | `DOCXThreatAnalyzer` | `<w:updateFields w:val="true"/>` in `word/settings.xml` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (element stripped from `word/settings.xml`) |
| **Mail Merge Configuration** | `DOCXThreatAnalyzer` | `<w:mailMerge>` element in `word/settings.xml` | `POLICY_VIOLATION` / `HIGH` | **YES** | **YES** (element stripped from `word/settings.xml`) |
| **External Attached Template** | `DOCXThreatAnalyzer` | Relationship type `.../attachedTemplate` with `TargetMode="External"` | `THREAT` / `CRITICAL` | **YES** | **YES** (relationship + XML reference removed) |
| **Macro-Enabled Attached Template** | `DOCXThreatAnalyzer` | Internal `attachedTemplate` targeting `.dotm` or macro-enabled content type | `THREAT` / `CRITICAL` | **YES** | **YES** (relationship + template part removed) |
| **Active altChunk Import** | `DOCXThreatAnalyzer` | `altChunk` part containing HTML scripts (`<script>`, `<object>`, `<iframe>`, `javascript:`) or macro-enabled content | `THREAT` / `HIGH` | **YES** | **YES** (altChunk part + relationship removed) |
| **Passive altChunk Import** | `DOCXThreatAnalyzer` | `altChunk` part containing clean static HTML/RTF without active content | `OBSERVATION` / `INFO` | **NO** | **Preserved after safe verification** |
| **Mail Merge Data Source Rel** | `DOCXThreatAnalyzer` | Relationship type `.../mailMergeSource` | `THREAT` / `HIGH` | **YES** | **YES** (relationship removed) |
| **Mail Merge Recipient Data Rel** | `DOCXThreatAnalyzer` | Relationship type `.../recipientData` | `POLICY_VIOLATION` / `MEDIUM` | **YES** | **YES** (relationship removed) |
