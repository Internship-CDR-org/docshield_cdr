# PPTX Security Surface Inventory

This is the implementation inventory for the current PPTX CDR pass. It is a capability/structure inventory, not a list of antivirus signatures.

| Surface | Detection | Sanitization | Reconstruction boundary |
|---|---|---|---|
| ZIP/package path traversal | Yes | Reject/remove | OOXML package reader/writer |
| ZIP entry/size abuse | Yes | Reject | OOXML package reader |
| Secure XML parser controls | Yes | Reject unsafe XML | OOXML package reader |
| VBA project/companion parts | Yes | Remove part + references | Common OOXML sanitizer |
| VBA relationship | Yes | Remove relationship | Common OOXML sanitizer |
| ActiveX/control parts | Yes | Remove part + references | Common OOXML sanitizer |
| PPTX ctrlProps | Yes | Remove part + references | Common OOXML sanitizer |
| OLE objects | Yes/observation + deep OLE inspection | Remove when unsafe | Common OOXML sanitizer |
| OLE VBA streams | Yes | Remove containing OLE | Common OOXML sanitizer |
| Ole10Native payloads | Yes | Remove containing object when policy blocks | Common OOXML sanitizer |
| Native executable payloads | Yes (PE/ELF/Mach-O/shebang + extensions) | Remove | Common OOXML sanitizer |
| Nested OOXML embedded package | Yes, bounded recursive inspection | Remove outer unsafe package boundary | Common OOXML sanitizer |
| External relationships | Yes | Remove when non-hyperlink/active or dangerous | Common OOXML sanitizer |
| Dangerous URI schemes | Yes | Remove relationship | Common OOXML sanitizer |
| Normal HTTPS hyperlink | Observation | Preserve | OOXML writer |
| Program/macro/OLE actions | Yes | Remove action element/attribute + relationship | Common OOXML sanitizer |
| External file/presentation actions | Yes | Remove action element/attribute + relationship | Common OOXML sanitizer |
| SVG script/event handler | Yes | Remove unsafe SVG | Common OOXML sanitizer |
| SVG dangerous/external URI | Yes | Remove unsafe SVG | Common OOXML sanitizer |
| XML DOCTYPE/ENTITY | Yes | Sanitize/reject construct | Common OOXML sanitizer + secure parser |
| DDE/DDEAUTO | Yes where represented in OOXML XML | Remove construct | Common OOXML sanitizer |
| Dangling r:id/r:embed/r:link in PPTX XML | Yes | Remove invalid reference | Common OOXML sanitizer |
| Missing local relationship target | Validator/common relationship analysis | Reject/repair policy | OOXML validator |
| Content-type declaration for removed part | Yes via package mutation | Remove declaration | OOXML writer |
| Slide/slide-master/layout/notes relationships | Graph-level coverage | Policy applied through relationship analyzer | OOXML writer |
| Chart/diagram/media/model3D external active relationships | Graph-level coverage | Remove external active relationship | OOXML writer |

## Important limitation

No CDR can guarantee detection of an unknown parser vulnerability merely from a document's observable structure. The security boundary therefore also relies on strict parsing, package limits, safe XML processing, validation, and package-preserving reconstruction.
