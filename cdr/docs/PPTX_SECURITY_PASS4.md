# PPTX Security Pass 4

## Scope

This pass hardens PresentationML coverage at the package-graph and XML-semantic boundary. It does not rely on antivirus vendor names.

## Added coverage

- Dangling `r:id`, `r:embed`, and `r:link` references in `ppt/` XML are detected as invalid relationships and removed by the common sanitizer.
- External PowerPoint resource relationships for media, charts, diagrams, model/3D media, slides, layouts, masters, notes, packages, OLE and controls are treated as external active resources rather than silently preserved.
- Existing program/macro/OLE action detection is applied across all `ppt/` XML parts, not only slide XML.
- Normal HTTPS external hyperlinks remain observations and are preserved.

## Security principle

The analyzer classifies document capabilities. It does not attempt to match malware-family names, CVEs, or VirusTotal labels. The common OOXML sanitizer applies the security action; PPTX-specific code only supplies PresentationML semantics.

## Files

Added: `src/test/java/threat/pptx/PPTXSecuritySurfaceTest.java`
Modified: `src/main/java/threat/ooxml/OOXMLThreatAnalyzer.java`, `src/main/java/sanitization/common/OOXMLThreatSanitizer.java`

## Verified design boundary

This pass does **not** claim that every future Office vulnerability can be detected. Instead, it closes currently identifiable PresentationML/OPC structural attack surfaces that can be represented in the package: active actions, external active resources, relationship-reference integrity, embedded content boundaries, and the previously implemented VBA/ActiveX/OLE/SVG/XML/package checks. Unknown or unsupported content is not converted into a malware signature; it remains subject to package validation and the existing reconstruction policy.

## PPTX security surface inventory

- Package/ZIP boundary: duplicate entries, traversal, size limits, secure XML parsing.
- OPC relationships: external targets, dangerous URI schemes, active relationship types, missing local targets, dangling XML relationship references.
- Active code: VBA projects, ActiveX/control parts, embedded native executables/scripts, OLE VBA streams.
- Interactive actions: program, macro, OLE, external-file and external-presentation actions.
- Embedded content: OLE objects and nested OOXML packages with bounded recursion.
- Vector resources: active SVG constructs and external SVG references.
- XML: DOCTYPE/ENTITY constructs and DDE/DDEAUTO detection where applicable.
- Package metadata: content-type declarations are regenerated after sanitization.

Normal HTTPS hyperlinks remain preservable content; they are not treated as executable payloads solely because they are external.


## Regression correction

During real-sample verification, the common sanitizer was found to treat an `OLE_OBJECT` observation as a removal authorization. That would unnecessarily destroy legitimate embedded OLE content. The sanitizer now distinguishes **observation** from **sanitization authorization** and preserves observed embedded/OLE objects unless the finding is non-observational (for example, an active VBA stream or blocked executable payload). A regression test covers this behavior.
