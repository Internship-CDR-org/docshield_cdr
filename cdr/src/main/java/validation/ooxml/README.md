# OOXML Integrity Validation Subsystem (`validation.ooxml`)

The `validation.ooxml` package provides post-reconstruction structural and relational integrity verification for OPC / OOXML packages (`DOCX`, `PPTX`, `XLSX`).

---

## 1. Architectural Purpose

When DocShield disarms a package by stripping active XML tags, deleting threat-bearing binary parts (macros, OLE objects, controls), and removing relationships, the resulting document must remain compliant with the Open Packaging Conventions (OPC) specification. 

[`OOXMLIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/ooxml/OOXMLIntegrityValidator.java) performs comprehensive graph validation on the re-read output package to verify that no broken pointers or malformed structures were introduced during sanitization and serialization.

---

## 2. Validation Checks in `OOXMLIntegrityValidator`

### A. Core Package Checks (`validate(OOXMLPackage packageData)`)
1. **`[Content_Types].xml` Presence**: Confirms the package contains `[Content_Types].xml` and that the content-types mapping table is non-empty.
2. **Part Name Normalization & Uniqueness**:
   - Confirms every part has a valid, non-blank name.
   - Rejects part names containing path traversals (`..`).
   - Ensures part names are strictly unique across the package.
3. **Content Type Coverage**:
   - Ensures every part in the package has a resolvable MIME type (either via explicit `<Override>` or by matching a registered `<Default>` extension).
   - Confirms that every explicit `<Override PartName="...">` declaration points to a part that actually exists in the package (no orphaned overrides).
4. **Relationship Graph Integrity**:
   - Ensures every relationship has non-blank `Id`, `Type`, and `Target` fields.
   - Enforces unique `(SourcePart, RelationshipId)` keys (no duplicate relationship IDs per part).
   - Verifies that the source part of each relationship exists in the package.
   - **Internal Target Resolution**: Resolves relative path targets (e.g., `../media/image1.png` relative to `word/document.xml` -> `word/media/image1.png`), checks for path traversals, and asserts that every internal target exists physically in the package.

### B. Original vs Reconstructed Comparison (`validate(original, reconstructed)`)
- Compares the reconstructed package against the original package to verify that no unexpected or uninvented parts were injected (every part in the output must have existed in the original document).

---

## 3. Integration in Processors

Called by [`DOCXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/docx/DOCXCDRProcessor.java), [`PPTXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pptx/PPTXCDRProcessor.java), and [`XLSXCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/xlsx/XLSXCDRProcessor.java) during the post-reconstruction verification loop. If `validate()` returns `false`, `integrityPassed` is set to `false`, causing `Main.java` to safely delete the output file and quarantine the input.
