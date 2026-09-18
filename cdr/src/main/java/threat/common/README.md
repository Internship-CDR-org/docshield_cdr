# Common Threat Model (`threat.common`)

## Overview

The `threat.common` package defines the universal data models, classification taxonomies, severity scales, and analyzer interfaces used across all document formats in DocShield CDR.

---

## Core Enumerations & Data Structures

### 1. [`FindingClassification`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/FindingClassification.java)
Defines the semantic meaning of an inspection finding:
- **`OBSERVATION`**: Informational finding that is not inherently malicious (e.g., standard HTTP/HTTPS hyperlinks, presence of embedded images, benign OLE storage). **Non-blocking** for release.
- **`POLICY_VIOLATION`**: Content that violates explicit organizational CDR security policies (e.g., external workbook links, external non-hyperlink resource references, automatic field updating). **Blocks release** until disarmed.
- **`SUSPICIOUS`**: Structurally anomalous content requiring deeper inspection or sanitization (e.g., dangling relationship references, missing relationship target parts, unparseable OLE streams). **Blocks release** until disarmed.
- **`THREAT`**: Confirmed active execution or high-risk capability (e.g., VBA macros, ActiveX controls, DDE/DDEAUTO commands, PE/ELF/Mach-O native payloads, dangerous URIs, malicious XML). **Blocks release** until disarmed.

---

### 2. [`ThreatSeverity`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/ThreatSeverity.java)
Represents risk level: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

---

### 3. [`ThreatType`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/ThreatType.java)
Capability-based threat classifications:
- **Active Code & Controls**: `VBA_PROJECT`, `ACTIVEX_OBJECT`, `XLM_MACRO`, `DDE`, `SCRIPT_CONTENT`, `DANGEROUS_ACTION`, `ACTIVE_FORMULA`.
- **Payloads & Embedded Storage**: `EXECUTABLE_PAYLOAD`, `EMBEDDED_OBJECT`, `EMBEDDED_PACKAGE`, `EMBEDDED_ACTIVE_CONTENT`, `OLE_OBJECT`, `BINARY_RESOURCE`.
- **External Connections & URIs**: `DANGEROUS_URI`, `EXTERNAL_HYPERLINK`, `EXTERNAL_REFERENCE`, `EXTERNAL_RESOURCE`, `EXTERNAL_TEMPLATE`, `EXTERNAL_CONNECTION`, `EXTERNAL_WORKBOOK`.
- **Structural, XML & Archive Risks**: `MALICIOUS_XML`, `SUSPICIOUS_XML`, `PATH_TRAVERSAL`, `SUSPICIOUS_ARCHIVE`, `SUSPICIOUS_BINARY`, `SUSPICIOUS_SVG`, `SVG_RESOURCE`, `MISSING_TARGET`, `INVALID_RELATIONSHIP`, `UNSUPPORTED_CONTENT`.
- **PDF Specific**: `PDF_JAVASCRIPT`, `PDF_ACTIVE_ACTION`, `PDF_EMBEDDED_FILE`, `PDF_XFA`, `PDF_RICH_MEDIA`, `PDF_RESOURCE_LIMIT`, `PDF_SIGNATURE`, `PDF_ENCRYPTION`.
- **General/Media**: `UNKNOWN`, `IMAGE_RESOURCE`, `AUDIO_RESOURCE`, `VIDEO_RESOURCE`, `SUSPICIOUS_MEDIA`, `AUTO_UPDATE_FIELDS`.

---

### 4. [`SecurityFinding`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/SecurityFinding.java)
An immutable observation record containing:
- `classification`: `FindingClassification`
- `type`: `ThreatType`
- `severity`: `ThreatSeverity`
- `part`: Associated `OOXMLPart` (if OOXML)
- `sourcePart`: URI/path of the originating source part
- `relationshipId`: ID of the affected relationship (if relationship-based)
- `evidence`: Concrete matching pattern, stream name, or raw evidence string
- `description`: Technical explanation of the detected capability
- `recommendedAction`: Prescribed sanitization action

---

### 5. Interfaces
- [`SecurityAnalyzer<T>`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/SecurityAnalyzer.java): Universal inspection contract `List<SecurityFinding> analyze(T data)`.
- [`ThreatAnalyzer<T>`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/ThreatAnalyzer.java): Marker interface for threat analyzers.
