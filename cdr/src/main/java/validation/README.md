# Validation Subsystem (`validation`)

The `validation` package contains structural and logical integrity validators used to verify reconstructed document artifacts before release.

---

## 1. Architectural Purpose: Integrity vs. Security

DocShield strictly separates **Security Validation** from **Structural Integrity Validation**:

```
Reconstructed Document Output
       │
       ├─► 1. Structural Integrity Validation (validation.*)
       │      • Did reconstruction produce a well-formed package?
       │      • Are all internal relationship targets resolvable?
       │      • Are page trees, media boxes, and catalog structures accessible?
       │
       └─► 2. Security Re-analysis (threat.*)
              • Did disarming leave any residual or newly exposed threats?
              • Are nested embedded packages clean?
              • Is the post-CDR object pool free of executable or script surfaces?
```

A document that is structurally valid may still be insecure, and a document that is secure may have suffered structural corruption during transformation. Release requires passing **both** gates unconditionally (`integrityPassed == true && threatsRemoved == true`).

---

## 2. Subpackage Breakdown

```
validation/
├── README.md                      # This architectural document
├── ooxml/
│   ├── README.md                  # OOXML package structural integrity rules
│   └── OOXMLIntegrityValidator.java # OPC part, relationship, and content-type validator
└── pdf/
    ├── README.md                  # PDF object graph integrity rules
    └── PDFIntegrityValidator.java # PDFBox page tree, resource, and catalog validator
```

- [`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java): Validates reconstructed `DOCX`, `PPTX`, and `XLSX` packages to ensure no path traversals, duplicate part names, missing content type overrides, or dangling internal relationship targets exist.
- [`PDFIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/pdf/PDFIntegrityValidator.java): Validates reconstructed `PDF` documents by forcing structural resolution of all pages, media boxes, resource dictionaries, annotation arrays, and catalog trees to detect serialization corruption.
