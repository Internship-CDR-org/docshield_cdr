# Common Threat Model

`SecurityFinding`, `ThreatType`, severity/classification and the common analyzer contracts are format-neutral. DOCX, XLSX and PPTX share the common OOXML structural analyzer; PDF/RTF/legacy formats can plug in format-specific analyzers without changing the common security model.
