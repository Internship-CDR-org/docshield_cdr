package processing.pdf;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import processing.common.CDRResult;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class PDFCDRProcessorTest {
    @Test
    void reconstructsCleanPdfAndRemovesOpenActionJavascript() throws Exception {
        Path input = Files.createTempFile("docshield-pdf-input-", ".pdf");
        Path output = Files.createTempFile("docshield-pdf-output-", ".pdf");
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            var action = new org.apache.pdfbox.cos.COSDictionary();
            action.setItem(COSName.S, COSName.getPDFName("JavaScript"));
            action.setString(COSName.JS, "app.alert('test')");
            document.getDocumentCatalog().getCOSObject().setItem(COSName.OPEN_ACTION, action);
            document.save(input.toFile());
        }

        CDRResult result = new PDFCDRProcessor().process(input, output);
        assertTrue(result.isReconstructionSuccessful());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.isThreatRemoved());

        try (PDDocument sanitized = org.apache.pdfbox.Loader.loadPDF(output.toFile())) {
            assertNull(sanitized.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.OPEN_ACTION));
            assertEquals(1, sanitized.getNumberOfPages());
        }

        Files.deleteIfExists(input);
        Files.deleteIfExists(output);
    }
}
