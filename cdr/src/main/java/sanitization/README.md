# Sanitization

Sanitization uses a common policy-driven contract. `sanitization.common.OOXMLThreatSanitizer` handles physical OPC/OOXML threats for DOCX, XLSX, and PPTX. Format entry points delegate to this common sanitizer.

The common sanitizer removes unsafe relationships/parts, cleans content-type declarations, and performs targeted XML disarming for DDE and dangerous XML declarations.

The architecture is intentionally extensible to PDF, RTF, and other formats: threat categories and the sanitizer contract are common, while structural mutation remains format-aware.
