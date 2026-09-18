package parsing.docx;

import model.common.DocumentModel;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DOCXParserIRTest {

    @Test
    void parsesTextAndImagesIntoCommonIr() throws Exception {
        Path input = Path.of("samples", "Pardhu_WebDeveloper_Resume.docx");
        assertTrue(Files.exists(input), "DOCX sample is missing: " + input.toAbsolutePath());

        DocumentModel model = new DOCXParser().parse(input);

        assertFalse(model.getTextComponents().isEmpty(),
                "DOCX text was not populated into the common IR");
        assertTrue(model.getTextComponents().stream().anyMatch(c ->
                        c.getText() != null && !c.getText().isBlank()),
                "DOCX IR text is blank");

        for (var image : model.getImageComponents()) {
            assertNotNull(image.getFileName());
            assertNotNull(image.getData());
            assertTrue(image.getData().length > 0);
        }
    }
}
