package application;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import static org.junit.jupiter.api.Assertions.*;

class UserFacingErrorTest {
    @Test
    void missingFileIsHumanReadable() {
        String message = UserFacingError.message(
                new NoSuchFileException("missing.docx"),
                Path.of("missing.docx"),
                Path.of("out.docx"));
        assertTrue(message.toLowerCase().contains("doesn't exist"));
    }

    @Test
    void malformedZipIsHumanReadable() {
        String message = UserFacingError.message(
                new java.util.zip.ZipException("zip END header not found"),
                Path.of("bad.pptx"),
                Path.of("out.pptx"));
        assertTrue(message.toLowerCase().contains("damaged") || message.toLowerCase().contains("valid"));
    }
}
