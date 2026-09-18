# PDF Integrity Validation Subsystem (`validation.pdf`)

The `validation.pdf` package provides post-reconstruction structural integrity validation for PDF documents.

---

## 1. Architectural Purpose

During PDF CDR, active actions, multimedia annotations, script name trees, and digital signature widgets are stripped, and the remaining COS object graph is serialized to a new PDF file via Apache PDFBox. 

A successful file save operation is not sufficient to guarantee that the output document is usable. PDF viewers can crash or reject documents if cross-reference streams, page trees, or resource dictionaries are corrupted during mutation.

[`PDFIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/pdf/PDFIntegrityValidator.java) re-opens the freshly saved PDF from disk and systematically traverses core structural paths to ensure the document can be completely parsed and rendered.

---

## 2. Validation Checks in `PDFIntegrityValidator`

When `validate(PDDocument document)` is called on the reloaded output document:

1. **Page Count Verification**: Asserts `document.getNumberOfPages() > 0`.
2. **Page Node Traversal**: Iterates through every [`PDPage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/pdf/PDFIntegrityValidator.java) in the document's page tree:
   - Verifies the underlying COS dictionary object exists.
   - Forces resolution of `page.getMediaBox()` to confirm page boundary geometry is valid.
   - Forces resolution of `page.getResources()` to confirm font, image, and color space dictionaries are readable.
   - Forces resolution of `page.getAnnotations()` to verify the sanitized annotation array is uncorrupted.
3. **Catalog Resolution**:
   - Asserts the Document Catalog dictionary exists.
   - Forces resolution of `documentCatalog.getPages()`.
   - Forces resolution of `documentCatalog.getNames()`.
   - Forces resolution of `documentCatalog.getAcroForm()`.

If any of these accesses throw an exception or return a null root, `validate()` returns `false`.

---

## 3. Integration in `PDFCDRProcessor`

Called in [`PDFCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pdf/PDFCDRProcessor.java) immediately after re-opening the written PDF. If `validate()` fails, the output file is deleted and the input is quarantined.
