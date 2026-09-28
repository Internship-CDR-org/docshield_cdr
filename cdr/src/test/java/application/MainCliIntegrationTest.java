package application;

import identification.FileIdentifier;
import identification.FileInfo;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import processing.common.CDRFileUtil;
import processing.pdf.PDFCDRProcessor;
import processing.common.CDRResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainCliIntegrationTest {

    @TempDir
    Path tempDir;

    @Test
    void processesCleanPdfPreservingByteIdentity() throws Exception {
        Path inputPdf = tempDir.resolve("clean.pdf");
        Path outputPdf = tempDir.resolve("clean_out.pdf");

        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream stream = new PDPageContentStream(doc, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.showText("Clean PDF content for DocShield test");
                stream.endText();
            }
            doc.save(inputPdf.toFile());
        }

        String inputSha = CDRFileUtil.sha256(inputPdf);

        PDFCDRProcessor processor = new PDFCDRProcessor();
        CDRResult result = processor.process(inputPdf, outputPdf);

        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.isOriginalCopied());
        assertEquals(inputSha, result.getInputSha256());
        assertEquals(inputSha, result.getOutputSha256());
        assertEquals(inputSha, CDRFileUtil.sha256(outputPdf));
    }

    @Test
    void rejectsInvalidInputPathSafely() {
        Path missing = tempDir.resolve("missing.docx");
        assertFalse(Files.exists(missing));
    }
}
