# Sanitization Subsystem (`sanitization`)

The `sanitization` package contains the content disarming engines responsible for neutralizing threats and policy violations discovered during security analysis. Rather than attempting ad-hoc redaction or surface string replacements, DocShield's sanitizers mutate structured document object graphs and package hierarchies to eliminate active capabilities while preserving benign document content and visual layout.

---

## 1. Architectural Role & Principles

1. **Graph-Level Mutation Boundary**: For Open Packaging Conventions (OPC) formats (`DOCX`, `PPTX`, `XLSX`), sanitization operates directly on the [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) in-memory data structure. For PDF, it mutates the Apache PDFBox [`PDDocument`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java) object graph.
2. **Finding-Driven Actions**: Sanitization is strictly guided by the [`List<SecurityFinding>`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/SecurityFinding.java) emitted by the threat analyzers.
3. **Observation Preservation**: Harmless observations (such as standard external web hyperlinks `http://` / `https://` or benign static images) are intentionally preserved. Only actionable classifications (`THREAT`, `POLICY_VIOLATION`, `SUSPICIOUS`) trigger destructive disarming.
4. **Structural Cleanup & Graph Closure**: Deleting an unsafe part or relationship automatically triggers package-wide cleanup:
   - Removal of incoming relationships targeting the deleted part.
   - Stripping of XML attributes (`r:id`, `r:embed`, `r:link`) referencing the deleted relationship ID.
   - Deletion of orphaned `[Content_Types].xml` `<Override>` declarations.
5. **Reconstruction & Re-verification Mandate**: Sanitization alone does not guarantee a safe document. Sanitized packages must undergo reconstruction via [`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java) (or PDF serialization), followed by mandatory re-parsing, re-analysis, and integrity verification.

---

## 2. Package Architecture

```
sanitization/
├── README.md                      # This architectural document
├── common/                        # Common contracts and OOXML sanitizers
│   ├── Sanitizer.java             # Generic interface for format sanitizers
│   ├── OOXMLThreatSanitizer.java  # Shared OPC/OOXML graph mutation engine
│   └── RecursiveOOXMLSanitizer.java # Deep CDR engine for nested packages/OLE
├── docx/
│   ├── README.md                  # DOCX sanitization specifics
│   └── DOCXThreatSanitizer.java   # Thin adapter delegating to OOXMLThreatSanitizer
├── pptx/
│   ├── README.md                  # PPTX sanitization specifics
│   └── PPTXThreatSanitizer.java   # Thin adapter delegating to OOXMLThreatSanitizer
├── xlsx/
│   ├── README.md                  # XLSX sanitization specifics
│   └── XLSXThreatSanitizer.java   # Thin adapter delegating to OOXMLThreatSanitizer
└── pdf/
    ├── README.md                  # PDF sanitization specifics
    └── PDFThreatSanitizer.java    # Native PDFBox catalog and annotation disarmer
```

---

## 3. Subpackage Breakdown

### `sanitization.common`
- [`Sanitizer<T>`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/Sanitizer.java): Generic interface defining `List<String> sanitize(T document, List<SecurityFinding> findings)`.
- [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java): The core OOXML mutation engine. Handles part removals, relationship severance, XML element/attribute cleanup, XML DTD/entity stripping, Word field disarming, PowerPoint action stripping, and Excel formula sanitization.
- [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java): Recursively unpacks embedded OOXML packages (and OOXML packages embedded inside OLE storages), sanitizes them in-memory against depth and size bounds, reconstructs them, and re-injects them into the outer package. If a nested payload remains unsafe or exceeds resource limits, it is removed entirely.

### `sanitization.docx`, `pptx`, `xlsx`
- Thin format-specific entry points ([`DOCXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/docx/DOCXThreatSanitizer.java), [`PPTXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pptx/PPTXThreatSanitizer.java), [`XLSXThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/xlsx/XLSXThreatSanitizer.java)) delegating to [`OOXMLThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/OOXMLThreatSanitizer.java).

### `sanitization.pdf`
- [`PDFThreatSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java): Operates directly on Apache PDFBox [`PDDocument`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java). Removes active JavaScript name trees, arbitrary `EmbeddedFiles` name trees, Document and Page `AA` (Additional Actions) dictionaries, catalog `OpenAction` dictionaries, active `XFA` forms, digital signature fields (preventing invalid post-CDR signatures), and active page annotations (`FileAttachment`, `RichMedia`, `3D`, `Movie`, `Sound`, `Screen`).
