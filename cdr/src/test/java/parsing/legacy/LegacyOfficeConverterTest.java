package parsing.legacy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import parsing.ppt.PPTToPPTXConverter;
import parsing.xls.XLSToXLSXConverter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class LegacyOfficeConverterTest {
    @TempDir Path temp;

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    @AfterEach void clear() {
        System.clearProperty("docshield.libreoffice.command");
        System.clearProperty("docshield.libreoffice.timeout.seconds");
        System.clearProperty("docshield.libreoffice.max.output.bytes");
    }

    @Test
    void convertsPptWithFakeLibreOffice() throws Exception {
        Path script;
        if (isWindows()) {
            script = createScript("""
                    @echo off
                    setlocal enabledelayedexpansion
                    set "outdir="
                    set "input="
                    :loop
                    if "%~1"=="" goto done
                    if "%~1"=="--outdir" (
                        set "outdir=%~2"
                        shift
                        shift
                        goto loop
                    )
                    if "%~x1"==".ppt" (
                        set "input=%~1"
                        set "basename=%~n1"
                        shift
                        goto loop
                    )
                    shift
                    goto loop
                    :done
                    if not exist "!outdir!" mkdir "!outdir!"
                    <nul set /p="fake-pptx"> "!outdir!\\!basename!.pptx"
                    exit /b 0
                    """);
        } else {
            script = createScript("""
                    #!/usr/bin/env bash
                    outdir=""; input=""
                    while [ "$#" -gt 0 ]; do
                      case "$1" in --outdir) outdir="$2"; shift 2;; *.ppt) input="$1"; shift;; *) shift;; esac
                    done
                    mkdir -p "$outdir"
                    printf 'fake-pptx' > "$outdir/$(basename "$input" .ppt).pptx"
                    """);
        }
        Path input = temp.resolve("sample.ppt"); Files.writeString(input, "test");
        System.setProperty("docshield.libreoffice.command", script.toString());
        Path result = new PPTToPPTXConverter().convert(input);
        assertTrue(Files.exists(result));
        assertEquals("fake-pptx", Files.readString(result));
    }

    @Test
    void reportsXlsConversionFailure() throws Exception {
        Path script;
        if (isWindows()) {
            script = createScript("""
                    @echo off
                    >&2 echo simulated XLS conversion failure
                    exit /b 9
                    """);
        } else {
            script = createScript("""
                    #!/usr/bin/env bash
                    echo 'simulated XLS conversion failure' >&2
                    exit 9
                    """);
        }
        Path input = temp.resolve("sample.xls"); Files.writeString(input, "test");
        System.setProperty("docshield.libreoffice.command", script.toString());
        IOException e = assertThrows(IOException.class, () -> new XLSToXLSXConverter().convert(input));
        assertTrue(e.getMessage().contains("exit code 9"));
        assertTrue(e.getMessage().contains("simulated XLS conversion failure"));
    }

    private Path createScript(String body) throws IOException {
        String ext = isWindows() ? ".cmd" : ".sh";
        Path p = temp.resolve("fake-libreoffice" + ext);
        Files.writeString(p, body);
        if (!isWindows()) {
            assertTrue(p.toFile().setExecutable(true));
        }
        return p;
    }
}
