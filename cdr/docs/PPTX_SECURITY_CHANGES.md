# PPTX Security / Sanitization Changes

Date: 2026-09-01

This pass is intentionally focused on **PPTX** while keeping the security decision and package mutation logic in the common OOXML layer.

## Architecture used

```text
PPTX file
   |
   v
OOXMLPackageReader
   |
   v
OOXMLPackage
   |
   +--> OOXMLThreatAnalyzer       (common OOXML capabilities)
   |
   +--> PPTXThreatAnalyzer        (PPTX-only semantics)
   |
   v
OOXMLThreatSanitizer              (common security policy)
   |
   v
OOXMLPackageWriter
   |
   v
OOXMLIntegrityValidator
```

PPTX-specific parsing remains separate from package representation. PPTX now operates on `OOXMLPackage`, `OOXMLPart`, and `OOXMLRelationship` rather than a duplicate PPTX package model.

## Threat capabilities covered in this pass

| Capability | Detection | Sanitization |
|---|---|---|
| VBA project / signature / companion data | `ppt/*vbaProject*`, `vbaData.xml` | Remove part, incoming/outgoing relationships and content-type entry |
| ActiveX | `ppt/activeX/`, ActiveX/control content types | Remove part and relationships |
| ActiveX control persistence | `ppt/ctrlProps/` | Remove part and relationships |
| OLE / embedded object | `ppt/embeddings/`, OLE content type | Remove object and relationships |
| Native executable in embedding | extension + PE/ELF/Mach-O/shebang signatures | Remove payload and relationships |
| External non-hyperlink relationship | external relationship graph | Remove relationship and XML reference |
| Dangerous URI | `file:`, `javascript:`, `vbscript:`, `data:`, `ms-*`, `shell:`, etc. | Remove relationship and XML reference |
| PowerPoint program/macro/OLE action | `ppaction://program`, `ppaction://macro`, `ppaction://ole`, active action attributes | Remove action element/attribute and its relationship |
| Active SVG | script, event handlers, JavaScript/VBScript, foreignObject | Remove SVG and relationships |
| External SVG resource URI | external `href`/`xlink:href`/`src` URI | Remove SVG and relationships |
| XML DTD/entity | `DOCTYPE`, `ENTITY` | Strip unsafe declarations/custom entity references; parser also uses secure XML settings |
| Package path traversal | `..`/absolute unsafe package part path | Remove offending part if it reaches sanitization; reader rejects unsafe ZIP paths |

## Deliberately preserved

Ordinary external hyperlinks such as `https://example.com` remain observations rather than automatic threats. This avoids destroying normal presentation hyperlinks merely because they are external.

External **non-hyperlink** resources are treated differently because they can represent package content fetched from outside the document.

## Relationship cleanup

When a relationship is removed, the sanitizer now also attempts to remove the XML element carrying `r:id`, `r:embed`, or `r:link`. This is important for PPTX because leaving a dangling relationship reference can produce a structurally inconsistent presentation.

When a dangerous part is removed, the sanitizer also removes:

1. incoming relationships;
2. outgoing relationships from the removed part;
3. relationship-bearing XML references; and
4. the corresponding `[Content_Types].xml` entry.

## Files added

### `src/main/java/threat/pptx/PPTXThreatAnalyzer.java`

PPTX-specific extension point over the common OOXML analyzer. It currently adds PowerPoint control-persistence (`ppt/ctrlProps/`) detection while leaving package-wide capability detection in the common analyzer.

### `src/test/java/threat/pptx/PPTXThreatCoverageTest.java`

JUnit coverage for:

- PowerPoint program actions;
- VBA;
- ActiveX;
- control persistence;
- active SVG;
- external resource relationships;
- preservation of ordinary hyperlinks; and
- the supplied `pptx_embedded_bat.pptx` real test sample.

## Files modified

### `src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java`

Expanded structural detection for:

- PowerPoint ActiveX/control persistence;
- PowerPoint action URIs;
- active/external SVG content;
- additional native executable signatures;
- additional dangerous URI schemes; and
- PowerPoint active-content relationships.

### `src/main/java/sanitization/common/OOXMLThreatSanitizer.java`

Expanded the common sanitizer so that the same mutation policy can disarm PPTX threats without a separate PPTX-specific mutation implementation.

Important changes include relationship-bearing XML element cleanup and PowerPoint action removal.

### `src/main/java/processing/pptx/PPTXCDRProcessor.java`

The production PPTX processor now uses `PPTXThreatAnalyzer` as its threat-analysis entry point while continuing to use the common `OOXMLThreatSanitizer` and `OOXMLPackageWriter`.

## Files removed

**None in this PPTX security pass.**

The duplicate PPTX package-model removal happened in the previous OOXML-unification pass. This pass builds on that state.

## Verification performed

The test suite is compiled and executed with JDK 21 and Apache Maven (`mvn clean test`).

The following components are validated:
- common OOXML model;
- OOXML reader;
- OOXML writer;
- OOXML analyzer;
- PPTX threat analyzer;
- common OOXML sanitizer; and
- OOXML integrity validator.

Sample and synthetic test verification:
- `file_example_PPT_500kb.pptx` — no findings, reconstruction/integrity passed;
- Presentation with normal external hyperlinks — ordinary external hyperlinks preserved, reconstruction/integrity passed;
- `pptx_embedded_bat.pptx` — embedded OLE object removed, reconstruction/integrity passed.

Synthetic tests exercise program actions, VBA, ActiveX/control persistence, active SVG and external image relationships.
