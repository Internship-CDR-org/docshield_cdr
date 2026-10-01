package processing.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import processing.common.CDRFileUtil;
import processing.common.CDRResult;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PDFCleanCopySha256Test {
    @Test
    void cleanPdfIsCopiedWithoutReconstructionAndHashIsIdentical() throws Exception {
        Path input = Files.createTempFile("docshield-clean-input-", ".pdf");
        Path output = Files.createTempFile("docshield-clean-output-", ".pdf");
        try {
            try (PDDocument document = new PDDocument()) {
                document.addPage(new PDPage());
                document.save(input.toFile());
            }

            String inputHash = CDRFileUtil.sha256(input);
            CDRResult result = new PDFCDRProcessor().process(input, output);

            assertTrue(result.isOutputReady());
            assertFalse(result.isReconstructionSuccessful());
            assertTrue(result.isOriginalCopied());
            assertTrue(result.isIntegrityPassed());
            assertTrue(result.isThreatRemoved());
            assertEquals(inputHash, result.getInputSha256());
            assertEquals(inputHash, result.getOutputSha256());
            assertEquals(inputHash, CDRFileUtil.sha256(output));
            assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(output);
        }
    }
}
