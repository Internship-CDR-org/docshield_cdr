# Threat Detection Subsystem (`threat`)

## Overview

The `threat` package forms the detection core of DocShield CDR. Unlike traditional antivirus software that relies on fragile malware signature hashes or specific virus names, DocShield uses a **capability-based and structural inspection model**.

DocShield inspects document packages to detect **active capabilities**—features that allow a document to execute arbitrary code, launch external processes, communicate with remote networks, dynamically fetch remote templates, or exploit XML/archive parsers.

---

## Security Philosophy

1. **Capability-Based Detection**: Documents are inspected for active execution mechanisms (macros, ActiveX, DDE, OLE objects, external links, scripts, dangerous actions, external connections) rather than signature hashes.
2. **Least Trust & Fail-Closed**: Any uninspectable, damaged, malformed, or nested content exceeding resource budgets is classified as a blocking threat and routed to quarantine.
3. **Observation vs. Blocking**: Benign structural observations (e.g., standard external web hyperlinks, presence of standard embedded images) are retained as `OBSERVATION` findings and preserved, while active/dangerous capabilities (`THREAT`, `POLICY_VIOLATION`, `SUSPICIOUS`) block release until sanitized.
4. **Mandatory Post-Reconstruction Verification**: Sanitization is verified by re-parsing and re-analyzing the reconstructed output file to confirm all blocking threats are eliminated.

---

## Package Structure

- [`threat.common`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/README.md): Common classifications, threat types, severities, finding representations, and analyzer interfaces.
- [`threat.ooxml`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ooxml/README.md): Shared structural threat analysis and OLE compound document analysis for DOCX, PPTX, and XLSX.
- [`threat.docx`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/docx/README.md): Word-specific threat detection (Word fields, DDE, MACROBUTTON, attached templates, altChunk, settings).
- [`threat.pptx`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pptx/README.md): PowerPoint-specific threat detection (PresentationML interactive actions, ctrlProps, SVG active content, embedded payloads).
- [`threat.xlsx`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/xlsx/README.md): Excel-specific threat detection (XLM macro sheets, DDE formulas, external workbook links, active formula functions, data connections).
- [`threat.legacy`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/legacy/README.md): Pre-conversion threat analysis for legacy binary formats (DOC, PPT, XLS).
- [`threat.pdf`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/README.md): Multi-pass PDF security analyzer, embedded payload inspector, decoded stream inspector, and post-reconstruction surface verifier.
