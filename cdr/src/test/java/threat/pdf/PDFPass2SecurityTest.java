package threat.pdf;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import sanitization.pdf.PDFThreatSanitizer;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Regression coverage for PDF Pass 2 action, annotation and form surfaces. */
class PDFPass2SecurityTest {

    @Test
    void removesDangerousActionChainButKeepsSafeAction() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSDictionary safe = action("URI", "https://example.com");
            COSDictionary dangerous = action("JavaScript", null);
            dangerous.setString(COSName.JS, "app.alert('x')");

            COSArray chain = new COSArray();
            chain.add(safe);
            chain.add(dangerous);

            COSDictionary catalog = document.getDocumentCatalog().getCOSObject();
            COSDictionary rootAction = action("URI", "https://example.com");
            rootAction.setItem(COSName.NEXT, chain);
            catalog.setItem(COSName.OPEN_ACTION, rootAction);

            new PDFThreatSanitizer().sanitize(document, List.of());

            COSDictionary retained = (COSDictionary) catalog.getDictionaryObject(COSName.OPEN_ACTION);
            assertNotNull(retained);
            COSArray remaining = (COSArray) retained.getDictionaryObject(COSName.NEXT);
            assertNotNull(remaining);
            assertEquals(1, remaining.size());
        }
    }

    @Test
    void removesActiveAnnotationFromPageButKeepsPage() throws Exception {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            COSDictionary attachment = new COSDictionary();
            attachment.setItem(COSName.SUBTYPE, COSName.getPDFName("FileAttachment"));
            COSArray annotations = new COSArray();
            annotations.add(attachment);
            page.getCOSObject().setItem(COSName.ANNOTS, annotations);

            new PDFThreatSanitizer().sanitize(document, List.of());

            COSArray remaining = page.getCOSObject().getCOSArray(COSName.ANNOTS);
            assertNotNull(remaining);
            assertEquals(0, remaining.size());
            assertEquals(1, document.getNumberOfPages());
        }
    }

    @Test
    void removesXfaButPreservesAcroFormDictionary() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSDictionary form = new COSDictionary();
            form.setItem(COSName.getPDFName("XFA"), COSName.getPDFName("dummy"));
            form.setItem(COSName.getPDFName("Fields"), new COSArray());
            document.getDocumentCatalog().getCOSObject().setItem(COSName.ACRO_FORM, form);

            new PDFThreatSanitizer().sanitize(document, List.of());

            COSDictionary sanitized = (COSDictionary)
                    document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.ACRO_FORM);
            assertNotNull(sanitized);
            assertNull(sanitized.getDictionaryObject(COSName.getPDFName("XFA")));
            assertNotNull(sanitized.getDictionaryObject(COSName.getPDFName("Fields")));
        }
    }

    @Test
    void detectsPass2Surfaces() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSDictionary catalog = document.getDocumentCatalog().getCOSObject();
            COSDictionary form = new COSDictionary();
            form.setItem(COSName.getPDFName("XFA"), COSName.getPDFName("dummy"));
            catalog.setItem(COSName.ACRO_FORM, form);

            COSDictionary annotation = new COSDictionary();
            annotation.setItem(COSName.SUBTYPE, COSName.getPDFName("RichMedia"));
            COSArray annotations = new COSArray();
            annotations.add(annotation);
            document.getPage(0).getCOSObject().setItem(COSName.ANNOTS, annotations);

            var findings = new PDFThreatAnalyzer().analyze(document);
            assertTrue(findings.stream().anyMatch(f -> f.getType().name().equals("PDF_XFA")));
            assertTrue(findings.stream().anyMatch(f -> f.getType().name().equals("PDF_RICH_MEDIA")));
        }
    }

    private static COSDictionary action(String type, String uri) {
        COSDictionary action = new COSDictionary();
        action.setItem(COSName.S, COSName.getPDFName(type));
        if (uri != null) action.setString(COSName.URI, uri);
        return action;
    }
}
