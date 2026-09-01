package reconstruction;

import model.ooxml.OOXMLPackage;
import org.junit.jupiter.api.Test;
import parsing.ooxml.OOXMLPackageReader;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OOXMLPPTXRoundTripTest {
    @Test
    void pptxUsesTheCommonOoxmlPackageReaderAndWriter() throws Exception {
        Path input = Path.of("samples", "file_example_PPT_500kb.pptx");
        assertTrue(Files.exists(input), "PPTX sample is missing: " + input.toAbsolutePath());

        OOXMLPackageReader reader = new OOXMLPackageReader();
        OOXMLPackage original = reader.read(input);
        Path output = Files.createTempFile("docshield-pptx-", ".pptx");
        try {
            new OOXMLPackageWriter().write(original, output);
            OOXMLPackage roundTrip = reader.read(output);
            assertEquals(original.getPartCount(), roundTrip.getPartCount());
            assertEquals(original.getRelationshipCount(), roundTrip.getRelationshipCount());
            assertEquals(original.getContentTypes().size(), roundTrip.getContentTypes().size());
        } finally {
            Files.deleteIfExists(output);
        }
    }
}
