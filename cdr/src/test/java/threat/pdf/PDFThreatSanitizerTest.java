package threat.pdf;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import sanitization.pdf.PDFThreatSanitizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PDFThreatSanitizerTest {

    @Test
    void removesJavaScriptAndKeepsPage() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            var catalog = document.getDocumentCatalog().getCOSObject();
            var action = new org.apache.pdfbox.cos.COSDictionary();
            action.setItem(COSName.S, COSName.getPDFName("JavaScript"));
            action.setString(COSName.JS, "app.alert('x')");
            catalog.setItem(COSName.OPEN_ACTION, action);

            var findings = new PDFThreatAnalyzer().analyze(document);
            assertTrue(findings.stream().anyMatch(f -> f.getType().name().equals("PDF_JAVASCRIPT")));

            new PDFThreatSanitizer().sanitize(document, findings);
            assertNull(catalog.getDictionaryObject(COSName.OPEN_ACTION));
            assertEquals(1, document.getNumberOfPages());
        }
    }

    @Test
    void preservesHttpsUriAction() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            var action = new org.apache.pdfbox.cos.COSDictionary();
            action.setItem(COSName.S, COSName.URI);
            action.setItem(COSName.URI, new COSString("https://example.com"));
            document.getDocumentCatalog().getCOSObject().setItem(COSName.OPEN_ACTION, action);

            var findings = new PDFThreatAnalyzer().analyze(document);
            assertFalse(findings.stream().anyMatch(f -> f.getClassification().name().equals("THREAT")));
            new PDFThreatSanitizer().sanitize(document, findings);
            assertNotNull(document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.OPEN_ACTION));
        }
    }

    @Test
    void freshOutputCanBeReloaded() throws Exception {
        Path output = Files.createTempFile("docshield-pdf-cdr-", ".pdf");
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            document.save(output.toFile());
        }
        assertTrue(Files.size(output) > 0);
        try (PDDocument reread = org.apache.pdfbox.Loader.loadPDF(output.toFile())) {
            assertEquals(1, reread.getNumberOfPages());
        }
        Files.deleteIfExists(output);
    }
}
