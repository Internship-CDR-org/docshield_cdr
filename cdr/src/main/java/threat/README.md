# Threat Analysis

Threat analysis is capability/structure based rather than vendor-signature based.

`threat.ooxml.OOXMLThreatAnalyzer` is the common structural analyzer for DOCX, XLSX, and PPTX. Format-specific analyzers delegate to it where the physical package model is shared.

Vendor labels such as EICAR, Trojan, Loader, or CVE names are not hard-coded as malware identities. The engine analyzes the underlying document capability: macros, ActiveX, embedded objects, executable payloads, dangerous URIs, external templates/resources/connections, DDE, unsafe XML, and package-path abuse.
