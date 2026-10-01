# PDF Sanitization Subsystem (`sanitization.pdf`)

The `sanitization.pdf` package contains the PDF disarming engine for DocShield CDR.

---

## 1. Architectural Role

Unlike OOXML formats which are reconstructed from ZIP-packaged XML parts, PDF documents are processed by loading the document object graph into Apache PDFBox ([`PDDocument`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java)), mutating COS dictionaries and arrays in memory, and serializing a completely new PDF file to disk.

The PDF sanitizer removes active execution surfaces, arbitrary file attachments, active multimedia, and digital signatures (which are inherently invalidated by CDR transformation), while preserving visual layout, text streams, font resources, vector graphics, and standard benign hyperlinks.

---

## 2. PDF Finding to Action Mapping

| Threat / Component | COS Object Location | Sanitization Mechanism | Impact on Document |
|---|---|---|---|
| **Document JavaScript** | `Catalog -> /Names -> /JavaScript` | Removes `/JavaScript` name tree from `/Names` dictionary. | Document-level scripts disarmed. |
| **Document Embedded Files** | `Catalog -> /Names -> /EmbeddedFiles` | Removes `/EmbeddedFiles` name tree from `/Names` dictionary. | Arbitrary dropped payloads eliminated. |
| **Catalog OpenAction** | `Catalog -> /OpenAction` | Evaluates action dictionary/array: if action is blocking (`JavaScript`, `Launch`, `GoToR`, `GoToE`, `SubmitForm`, `ImportData`, `Rendition`, `Movie`, `Sound`, `RichMediaExecute`), the `/OpenAction` entry is deleted from catalog. | Automatic execution on document open blocked. |
| **Document Additional Actions** | `Catalog -> /AA` | Removes `/AA` dictionary (containing `WC`, `WS`, `DS`, `WP`, `DP` triggers). | Document lifecycle triggers neutralized. |
| **XFA Forms** | `Catalog -> /AcroForm -> /XFA` | Removes `/XFA` entry from `/AcroForm` dictionary. Standard AcroForm visual fields are preserved. | Active XML script forms disarmed. |
| **Digital Signatures** | `Catalog -> /AcroForm -> /Fields` | Prunes `/Sig` widget fields from form field array. (CDR rewrites the object pool, rendering pre-existing signatures invalid). | Prevents display of corrupted or misleading signature banners. |
| **Page Annotations** | `Page -> /Annots` | Iterates all page annotations: removes active types (`FileAttachment`, `RichMedia`, `3D`, `Movie`, `Sound`, `Screen`); removes blocking `/A` actions; removes `/AA` dictionary from annotation widgets. | Active interactive buttons and multimedia controls neutralized. |
| **Page Additional Actions** | `Page -> /AA` | Removes `/AA` dictionary (containing `O`, `C` triggers). | Page open/close triggers neutralized. |
| **Dangerous URI Actions** | `Annotation -> /A (Type: /Action, S: /URI)` | If `/URI` scheme is unsafe (`file:`, `javascript:`, `vbscript:`, `data:`, `ms-app:`, `shell:`, `mk:`, local drive `C:\`, UNC path `\\server\share`), the `/A` dictionary is removed from the annotation. Benign web URLs (`http:`, `https:`, `mailto:`) are preserved. | URI handler execution exploits blocked. |

---

## 3. Workflow Inside `PDFCDRProcessor`

1. Input validation checks file existence, regular file status, and size limit (`MAX_INPUT_BYTES = 200 MB`).
2. Apache PDFBox [`Loader.loadPDF`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pdf/PDFCDRProcessor.java) parses the document object graph. Page count limit checked (`MAX_PAGES = 10,000`).
3. Multi-pass security analysis is performed:
   - [`PDFThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFThreatAnalyzer.java) analyzes catalog, name trees, page trees, actions, and annotations.
   - [`PDFEmbeddedPayloadInspector`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFEmbeddedPayloadInspector.java) inspects raw bytes of embedded attachments.
4. If clean: original file is copied byte-for-byte with SHA-256 verification (`CDRFileUtil.copyOriginal`).
5. If actionable findings exist: [`PDFThreatSanitizer.sanitize`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/sanitization/pdf/PDFThreatSanitizer.java) mutates the loaded `PDDocument`.
6. Output is written first to an isolated temporary file (`.docshield-pdf-*.tmp`) and atomically renamed (`ATOMIC_MOVE` or replace) upon successful completion (`document.setAllSecurityToBeRemoved(true)` + `document.save()`).
7. The written output is re-loaded from disk and verified independently:
   - [`PDFIntegrityValidator`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/validation/pdf/PDFIntegrityValidator.java) verifies page structures, media boxes, resources, and catalog resolution.
   - [`PDFThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFThreatAnalyzer.java) re-analyzes the reconstructed PDF.
   - [`PDFSecuritySurfaceVerifier`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/pdf/PDFSecuritySurfaceVerifier.java) performs strict low-level COS object-pool scanning.
8. If residual threats remain or integrity fails, the output file is deleted and the input is quarantined.
