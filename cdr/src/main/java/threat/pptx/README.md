# PPTX Threat Components

PPTX threat handling is split deliberately:

- `threat.ooxml.OOXMLThreatAnalyzer` detects package-wide capabilities common to OOXML, such as VBA, ActiveX, embedded objects, executable payloads, external relationships, dangerous URIs, XML hazards and active SVG content.
- `PPTXThreatAnalyzer` adds PowerPoint-only package semantics that do not belong in the generic OOXML analyzer, currently including `ppt/ctrlProps/` ActiveX control-persistence parts.
- `Ole10NativeAnalyzer`, `PayloadIdentifier`, `PayloadFingerprint` and `SecurityPolicy` provide deeper inspection of OLE native payloads when the PPTX processor encounters an OLE compound object.
- `RelationshipAnalyzer`, `EmbeddedObjectAnalyzer`, `OLEAnalyzer`, `ResourceAnalyzer` and `SVGAnalyzer` remain specialized analysis utilities; the production CDR path uses the unified threat model rather than maintaining a second package representation.

No analyzer executes embedded content.
