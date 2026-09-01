# PPTX Sanitization

PPTX sanitization delegates to `sanitization.common.OOXMLThreatSanitizer`.

The common sanitizer applies the same security policy to the OOXML package graph used by DOCX, XLSX and PPTX. PPTX does not have a separate mutation implementation.

For PPTX this includes:

- VBA and companion-part removal;
- ActiveX and `ctrlProps` removal;
- OLE/embedded-object removal;
- executable payload removal;
- dangerous external relationship removal;
- dangerous URI removal;
- PowerPoint program/macro/OLE action removal;
- active/external SVG removal; and
- relationship/content-type cleanup.
