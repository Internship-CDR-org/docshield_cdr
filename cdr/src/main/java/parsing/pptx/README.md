# PPTX Parsing

PPTX physical package reading is handled by the common `parsing.ooxml.OOXMLPackageReader`.

PowerPoint-specific parsers in this directory interpret the already-read OOXML package or the PowerPoint presentation content. They do not define a second package representation.

Key components:

- `PPTXParser` — semantic document parsing.
- `PPTXContentParser` — slide text extraction.
- `PPTXStructureParser` — slide/shape structure extraction.
- `PPTXResourceParser` — PowerPoint resources.
- `PPTXLayoutParser` / `PPTXSlideLayoutParser` — layout semantics.
- `PPTXThemeParser` — theme semantics.
- `PPTXRelationshipGraph` — PowerPoint-oriented view over common `OOXMLRelationship` objects.
- `PPTXContentInspector` / `PPTXXmlInspector` — inspection utilities.
