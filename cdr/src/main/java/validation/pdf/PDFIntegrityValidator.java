package validation.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

/** Structural validation for reconstructed PDFs. */
public final class PDFIntegrityValidator {
    public boolean validate(PDDocument document) {
        if (document == null) return false;
        try {
            if (document.getNumberOfPages() <= 0) return false;
            for (PDPage page : document.getPages()) {
                if (page == null || page.getCOSObject() == null) return false;
                // Force resolution of common page structures. A successful save
                // alone is not enough; these accesses catch broken page/annotation
                // structures in the reconstructed document.
                page.getMediaBox();
                page.getResources();
                page.getAnnotations();
            }
            // Force access to the catalog, page tree, names and AcroForm after reconstruction.
            if (document.getDocumentCatalog() == null ||
                    document.getDocumentCatalog().getCOSObject() == null) return false;
            document.getDocumentCatalog().getPages();
            document.getDocumentCatalog().getNames();
            document.getDocumentCatalog().getAcroForm();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}
