package parsing.doc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class DOCToDOCXConverterTest {
    @TempDir Path tempDir;
    private static final String COMMAND_PROPERTY = "docshield.libreoffice.command";
    private static final String TIMEOUT_PROPERTY = "docshield.libreoffice.timeout.seconds";

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    @AfterEach
    void restoreProperties() {
        System.clearProperty(COMMAND_PROPERTY);
        System.clearProperty(TIMEOUT_PROPERTY);
        System.clearProperty("docshield.libreoffice.max.output.bytes");
    }

    @Test
    void convertsWithIsolatedSubprocessAndProducesDocx() throws Exception {
        Path fake;
        if (isWindows()) {
            fake = createScript("""
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
                    if "%~x1"==".doc" (
                        set "input=%~1"
                        set "basename=%~n1"
                        shift
                        goto loop
                    )
                    shift
                    goto loop
                    :done
                    if not exist "!outdir!" mkdir "!outdir!"
                    <nul set /p="fake-docx"> "!outdir!\\!basename!.docx"
                    exit /b 0
                    """);
        } else {
            fake = createScript("""
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
        }
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
        Path fake;
        if (isWindows()) {
            fake = createScript("""
                    @echo off
                    >&2 echo simulated corrupt DOC stream
                    exit /b 7
                    """);
        } else {
            fake = createScript("""
                    #!/usr/bin/env bash
                    echo 'simulated corrupt DOC stream' >&2
                    exit 7
                    """);
        }
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
        Path fake;
        if (isWindows()) {
            fake = createScript("""
                    @echo off
                    ping 127.0.0.1 -n 11 > nul
                    exit /b 0
                    """);
        } else {
            fake = createScript("""
                    #!/usr/bin/env bash
                    sleep 10
                    """);
        }
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
        Path fake;
        if (isWindows()) {
            fake = createScript("""
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
                    if "%~x1"==".doc" (
                        set "input=%~1"
                        set "basename=%~n1"
                        shift
                        goto loop
                    )
                    shift
                    goto loop
                    :done
                    if not exist "!outdir!" mkdir "!outdir!"
                    powershell -NoProfile -Command "[IO.File]::WriteAllBytes('!outdir!\\!basename!.docx', (New-Object byte[] 2048))"
                    exit /b 0
                    """);
        } else {
            fake = createScript("""
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
        }
        Path input = tempDir.resolve("sample.doc");
        Files.writeString(input, "controlled test input");
        System.setProperty(COMMAND_PROPERTY, fake.toString());
        System.setProperty("docshield.libreoffice.max.output.bytes", "1024");

        IOException error = assertThrows(IOException.class,
                () -> new DOCToDOCXConverter().convert(input));
        assertTrue(error.getMessage().contains("output resource limit"));
    }

    private Path createScript(String body) throws IOException {
        String ext = isWindows() ? ".cmd" : ".sh";
        Path script = tempDir.resolve("fake-libreoffice" + ext);
        Files.writeString(script, body);
        if (!isWindows()) {
            assertTrue(script.toFile().setExecutable(true));
        }
        return script;
    }
}
