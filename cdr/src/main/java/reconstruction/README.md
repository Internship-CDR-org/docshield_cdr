# Reconstruction Subsystem (`reconstruction`)

The `reconstruction` package provides the packaging and serialization engine that converts in-memory document representations into valid, standardized file artifacts.

---

## 1. Architectural Purpose

In Content Disarm and Reconstruction (CDR), reconstruction is the synthesis phase following sanitization. It ensures that:
1. All changes made during threat disarming (deleted parts, severed relationships, stripped XML elements) are cleanly reflected in the physical container format.
2. Package headers, content type maps, and relationship tables are regenerated dynamically from the sanitized state rather than copying stale metadata from the original untrusted file.
3. The output artifact conforms strictly to standard Open Packaging Conventions (ISO/IEC 29500-2 / ECMA-376).

---

## 2. Core Implementation: `OOXMLPackageWriter`

[`OOXMLPackageWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java) is the shared serialization engine used for `DOCX`, `PPTX`, `XLSX`, and nested embedded packages.

### Key Responsibilities

1. **Dynamic `[Content_Types].xml` Generation (`buildContentTypesXml`)**:
   - Reconstructs the root `[Content_Types].xml` part from scratch based on active Default extensions (e.g., `.xml`, `.rels`, `.png`, `.jpeg`) and explicit Override parts present in [`OOXMLPackage.getContentTypes()`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java).
   - Any part removed during sanitization (e.g., `vbaProject.bin`, `activeX1.xml`) has its `<Override>` entry completely omitted.

2. **Dynamic Relationship File Generation (`buildRelationshipXml`)**:
   - Rebuilds package-level (`_rels/.rels`) and part-level relationship files (e.g., `word/_rels/document.xml.rels`, `ppt/slides/_rels/slide1.xml.rels`).
   - Only active relationships remaining in the [`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java) graph are emitted as `<Relationship>` elements. Severed or dangerous relationships are never written.

3. **Safe ZIP Archive Serialization (`writeToStream`)**:
   - Streams every active part as a standard [`ZipEntry`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java) into a [`ZipOutputStream`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reconstruction/OOXMLPackageWriter.java).
   - Part names are normalized to standard forward-slash paths without leading slashes.

4. **In-Memory Byte Serialization (`writeToBytes`)**:
   - Serializes sanitized nested OOXML packages directly to a byte array (`byte[]`) in memory. Used by [`RecursiveOOXMLSanitizer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/common/RecursiveOOXMLSanitizer.java) to update embedded package byte arrays in-place without touching disk.

---

## 3. PDF Reconstruction

PDF documents do not use ZIP/OPC packaging. PDF reconstruction is performed inside [`PDFCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pdf/PDFCDRProcessor.java) using Apache PDFBox:
1. Disarmed [`PDDocument`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java) object graphs have security removed (`document.setAllSecurityToBeRemoved(true)`).
2. The sanitized object pool and cross-reference table are written to an isolated temporary file (`.docshield-pdf-*.tmp`).
3. Upon successful serialization, the file is atomically moved to the destination output path.
