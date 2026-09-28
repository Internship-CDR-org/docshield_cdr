# DOCX Security Pass 1

## Scope
This pass adds Word-specific threat detection on top of the common OOXML security model and routes sanitization through the existing common sanitizer.

## Added
- `src/main/java/threat/docx/DOCXThreatAnalyzer.java` — Word-specific analyzer for fragmented DDE/DDEAUTO fields, external field codes, automatic field updates, and mail-merge configuration.
- `src/main/java/threat/ooxml/OLEAnalyzer.java` — format-neutral OLE structural analyzer moved into the common OOXML threat layer.
- `src/test/java/threat/docx/DOCXSecuritySurfaceTest.java` — regression checks for fragmented DDE, automatic field updates, mail merge, and preservation of cached field results.

## Modified
- `src/main/java/threat/common/ThreatType.java` — adds `AUTO_UPDATE_FIELDS`.
- `src/main/java/sanitization/common/OOXMLThreatSanitizer.java` — disables automatic field updates, removes mail-merge configuration, and removes Word field instructions while preserving cached/displayed results.
- `src/main/java/threat/pptx/OLEAnalyzer.java` — compatibility wrapper to the common OLE analyzer.

## Removed
- No user-facing DOCX functionality was intentionally removed.
- The old PPTX-specific OLE implementation was replaced by a compatibility wrapper; OLE analysis now has a format-neutral implementation.

## Detection and sanitization policy
- VBA/ActiveX: remove the active package parts and relationships.
- DDE/DDEAUTO: remove the field instruction, including fragmented `w:instrText` fragments; preserve cached result text where possible.
- External Word field codes: remove the field instruction rather than deleting the entire document part.
- External attached templates: remove the external relationship and its XML reference.
- Dangerous external URI schemes: remove the relationship.
- External non-hyperlink resources/connections: remove the relationship or the associated active configuration.
- Automatic field update: remove `w:updateFields` set to true.
- Mail merge configuration: remove the external mail-merge configuration.
- OLE: inspect structurally; presence alone is not a removal decision.
- Executable/script embedded payloads: remove the unsafe package part and relationships.

## Verification
The dependency-free security/reconstruction layer was compiled with JDK 21. A real project sample (`samples/docx_embedded_vba.docx`) was read, VBA was removed, reconstructed, reread, and validated successfully. The synthetic DOCX security surface test also passed.

A full Maven/JUnit run has not been claimed because Maven/dependency artifacts are not available in the execution environment.
