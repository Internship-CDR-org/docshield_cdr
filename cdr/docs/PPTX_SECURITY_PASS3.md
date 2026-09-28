# PPTX Security Pass 3 — Recursive Embedded OOXML

## Purpose

This pass extends PPTX CDR from inspecting the outer PresentationML package to inspecting OOXML packages embedded inside PPTX package parts.

## Added

- `threat/ooxml/EmbeddedOOXMLAnalyzer.java`
- `src/test/java/threat/ooxml/EmbeddedOOXMLAnalyzerTest.java`

## Modified

- `parsing/ooxml/OOXMLPackageReader.java`
  - added in-memory `read(InputStream)` and `read(byte[])` support for nested package inspection.
- `reconstruction/OOXMLPackageWriter.java`
  - added `writeToBytes()` for in-memory nested-package reconstruction/testing.
- `processing/pptx/PPTXCDRProcessor.java`
  - invokes recursive embedded OOXML analysis.
- `sanitization/common/OOXMLThreatSanitizer.java`
  - removes an opaque embedded package when it contains blocking nested content or an unsafe nested archive condition.

## Policy

The outer embedded part is the sanitization boundary. If a nested OOXML package contains a blocking finding, DocShield removes the complete containing embedded package rather than attempting partial mutation inside an opaque binary payload.

This avoids leaving nested relationships or active content behind when the embedded object cannot be represented safely in the outer package model.

## Limits

- Maximum recursive embedded-package depth: 4
- Maximum individual embedded package inspected recursively: 64 MiB
- Nested packages must contain both `[Content_Types].xml` and `_rels/.rels` before they are treated as OOXML packages.

## Not yet covered by this pass

- Recursive inspection of OOXML packages stored inside OLE Compound File streams.
- Format-specific nested analysis beyond the common OOXML threat model.
- General recursive sanitization of arbitrary non-OOXML embedded file formats.
