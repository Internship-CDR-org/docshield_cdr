# PPTX CDR Processing

PPTX uses the same physical package pipeline as DOCX and XLSX:

`OOXMLPackageReader -> PPTXThreatAnalyzer -> common OOXML sanitization -> OOXMLPackageWriter -> OOXMLIntegrityValidator`

`PPTXThreatAnalyzer` is a thin PowerPoint-specific extension over the common OOXML threat analyzer. It does not introduce a separate package model.

PowerPoint-specific semantic parsing remains under `parsing.pptx` and is intentionally separated from package-level security analysis and sanitization.
