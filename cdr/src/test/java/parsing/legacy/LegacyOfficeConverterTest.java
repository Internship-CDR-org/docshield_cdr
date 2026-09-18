package parsing.legacy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import parsing.ppt.PPTToPPTXConverter;
import parsing.xls.XLSToXLSXConverter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class LegacyOfficeConverterTest {
    @TempDir Path temp;

    @AfterEach void clear() {
        System.clearProperty("docshield.libreoffice.command");
        System.clearProperty("docshield.libreoffice.timeout.seconds");
        System.clearProperty("docshield.libreoffice.max.output.bytes");
    }

    @Test
    void convertsPptWithFakeLibreOffice() throws Exception {
        Path script = script("""
                #!/usr/bin/env bash
                outdir=""; input=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in --outdir) outdir="$2"; shift 2;; *.ppt) input="$1"; shift;; *) shift;; esac
                done
                mkdir -p "$outdir"
                printf 'fake-pptx' > "$outdir/$(basename "$input" .ppt).pptx"
                """);
        Path input = temp.resolve("sample.ppt"); Files.writeString(input, "test");
        System.setProperty("docshield.libreoffice.command", script.toString());
        Path result = new PPTToPPTXConverter().convert(input);
        assertTrue(Files.exists(result));
        assertEquals("fake-pptx", Files.readString(result));
    }

    @Test
    void reportsXlsConversionFailure() throws Exception {
        Path script = script("#!/usr/bin/env bash\necho 'simulated XLS conversion failure' >&2\nexit 9\n");
        Path input = temp.resolve("sample.xls"); Files.writeString(input, "test");
        System.setProperty("docshield.libreoffice.command", script.toString());
        IOException e = assertThrows(IOException.class, () -> new XLSToXLSXConverter().convert(input));
        assertTrue(e.getMessage().contains("exit code 9"));
        assertTrue(e.getMessage().contains("simulated XLS conversion failure"));
    }

    private Path script(String body) throws IOException {
        Path p = temp.resolve("fake-libreoffice.sh"); Files.writeString(p, body); assertTrue(p.toFile().setExecutable(true)); return p;
    }
}
