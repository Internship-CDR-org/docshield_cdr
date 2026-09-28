# PPTX Security Pass 2

## Goal

Pass 2 strengthens the PPTX security boundary without creating a separate PPTX package/security engine. PPTX continues to use the common `OOXMLPackage`, `OOXMLPart`, `OOXMLRelationship`, `OOXMLThreatAnalyzer`, `OOXMLThreatSanitizer`, `OOXMLPackageWriter`, and `OOXMLIntegrityValidator` pipeline.

## Changes

### `threat/ooxml/OOXMLThreatAnalyzer.java`

- Embedded objects/packages are now **observations**, not automatic threats. Merely having `ppt/embeddings/*` is not sufficient evidence that the object is malicious.
- Relationship semantics are inspected even for internal relationships.
- VBA project relationships are classified as `VBA_PROJECT` threats.
- ActiveX/control relationships are classified as `ACTIVEX_OBJECT` threats.
- PowerPoint active action handling includes `ppaction://program`, `ppaction://macro`, `ppaction://ole`, `ppaction://hlinkfile`, and `ppaction://hlinkpres` forms when present in action attributes.

### `threat/pptx/PPTXThreatAnalyzer.java`

- Runs the common OOXML analyzer first.
- Runs `OLEAnalyzer` over actual OLE Compound File candidates.
- A generic embedded package is no longer treated as corrupt OLE merely because it lives under `/embeddings/`.
- Active OLE VBA streams can therefore become real `VBA_PROJECT` findings, while ordinary OLE structure remains an observation.

### `threat/pptx/OLEAnalyzer.java`

- OLE candidate detection now uses OLE content type or the actual Compound File signature.
- Generic embedded OOXML/package data is not misclassified as OLE.
- VBA streams/storage are promoted from informational observations to `THREAT` findings.

### `sanitization/common/OOXMLThreatSanitizer.java`

- PowerPoint active action sanitization covers program, macro, OLE, external-file and external-presentation action forms.
- Associated relationship IDs are removed when the action element carries `r:id`.
- Existing common relationship/XML/content-type cleanup remains the mutation boundary.

## Security principle

A package feature is not removed solely because it exists. The engine distinguishes:

- **capability/observation**: an object or relationship exists and needs inspection;
- **security finding**: the object has a dangerous capability or unsafe structure;
- **sanitization**: only the confirmed unsafe capability is removed or neutralized.

This avoids destroying every legitimate embedded object while still removing confirmed active content.

## Verification

The dependency-free common OOXML security layer was compiled with JDK 21 and exercised against the repository's real PPTX samples. The following checks passed:

- embedded BAT/OLE sample reconstructs and no longer contains the blocking common finding;
- ordinary external HTTPS hyperlinks remain preserved;
- clean PPTX remains unchanged by the sanitizer;
- `ppaction://hlinkfile` with a dangerous external `file:` relationship is detected and the relationship/XML reference is removed;
- reconstructed packages pass `OOXMLIntegrityValidator`.

A full Maven/JUnit run still requires the project's Maven/Apache POI dependencies to be available in the build environment.
