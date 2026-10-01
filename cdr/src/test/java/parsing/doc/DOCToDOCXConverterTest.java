package parsing.doc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DOCToDOCXConverterTest {
    @TempDir Path tempDir;
    private static final String COMMAND_PROPERTY = "docshield.libreoffice.command";
    private static final String TIMEOUT_PROPERTY = "docshield.libreoffice.timeout.seconds";

    @AfterEach
    void restoreProperties() {
        System.clearProperty(COMMAND_PROPERTY);
        System.clearProperty(TIMEOUT_PROPERTY);
        System.clearProperty("docshield.libreoffice.max.output.bytes");
    }

    @Test
    void convertsWithIsolatedSubprocessAndProducesDocx() throws Exception {
        Path fake = createScript("""
                #!/usr/bin/env bash
                outdir=""
                input=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --outdir) outdir="$2"; shift 2 ;;
                    *.doc) input="$1"; shift ;;
                    *) shift ;;
                  esac
                done
                base="$(basename "$input" .doc)"
                mkdir -p "$outdir"
                printf 'fake-docx' > "$outdir/$base.docx"
                """);
        Path input = tempDir.resolve("sample.doc");
        Files.writeString(input, "controlled test input");
        System.setProperty(COMMAND_PROPERTY, fake.toString());

        Path converted = new DOCToDOCXConverter().convert(input);
        assertTrue(Files.exists(converted));
        assertTrue(converted.getFileName().toString().endsWith(".docx"));
        assertEquals("fake-docx", Files.readString(converted));
    }

    @Test
    void reportsLibreOfficeFailureReason() throws Exception {
        Path fake = createScript("""
                #!/usr/bin/env bash
                echo 'simulated corrupt DOC stream' >&2
                exit 7
                """);
        Path input = tempDir.resolve("sample.doc");
        Files.writeString(input, "controlled test input");
        System.setProperty(COMMAND_PROPERTY, fake.toString());

        IOException error = assertThrows(IOException.class,
                () -> new DOCToDOCXConverter().convert(input));
        assertTrue(error.getMessage().contains("exit code 7"));
        assertTrue(error.getMessage().contains("simulated corrupt DOC stream"));
    }

    @Test
    void terminatesLibreOfficeWhenConversionTimesOut() throws Exception {
        Path fake = createScript("""
                #!/usr/bin/env bash
                sleep 10
                """);
        Path input = tempDir.resolve("sample.doc");
        Files.writeString(input, "controlled test input");
        System.setProperty(COMMAND_PROPERTY, fake.toString());
        System.setProperty(TIMEOUT_PROPERTY, "1");

        IOException error = assertThrows(IOException.class,
                () -> new DOCToDOCXConverter().convert(input));
        assertTrue(error.getMessage().contains("timed out after 1 seconds"));
    }

    @Test
    void rejectsConversionOutputThatExceedsConfiguredLimit() throws Exception {
        Path fake = createScript("""
                #!/usr/bin/env bash
                outdir=""
                input=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --outdir) outdir="$2"; shift 2 ;;
                    *.doc) input="$1"; shift ;;
                    *) shift ;;
                  esac
                done
                base="$(basename "$input" .doc)"
                mkdir -p "$outdir"
                dd if=/dev/zero of="$outdir/$base.docx" bs=1024 count=2 status=none
                """);
        Path input = tempDir.resolve("sample.doc");
        Files.writeString(input, "controlled test input");
        System.setProperty(COMMAND_PROPERTY, fake.toString());
        System.setProperty("docshield.libreoffice.max.output.bytes", "1024");

        IOException error = assertThrows(IOException.class,
                () -> new DOCToDOCXConverter().convert(input));
        assertTrue(error.getMessage().contains("output resource limit"));
    }

    private Path createScript(String body) throws IOException {
        Path script = tempDir.resolve("fake-libreoffice.sh");
        Files.writeString(script, body);
        assertTrue(script.toFile().setExecutable(true));
        return script;
    }
}
