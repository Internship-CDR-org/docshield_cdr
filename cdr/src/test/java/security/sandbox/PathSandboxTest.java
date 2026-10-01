package security.sandbox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PathSandboxTest {

    @TempDir
    Path jail;

    @Test
    void resolvesSafePathInsideJail() {
        Path resolved = PathSandbox.resolveSafe(jail, "safe/nested/file.txt");
        assertNotNull(resolved);
        assertTrue(resolved.startsWith(jail.toAbsolutePath().normalize()));
        assertEquals("file.txt", resolved.getFileName().toString());
    }

    @Test
    void blocksTraversalEscapingJail() {
        assertThrows(SecurityException.class, () -> PathSandbox.resolveSafe(jail, "../escaped.txt"));
        assertThrows(SecurityException.class, () -> PathSandbox.resolveSafe(jail, "sub/../../escaped.txt"));
        assertThrows(SecurityException.class, () -> PathSandbox.resolveSafe(jail, "/absolute/escape.txt"));
    }

    @Test
    void validatesTargetInsideBoundary() {
        Path inside = jail.resolve("legit.doc");
        assertDoesNotThrow(() -> PathSandbox.validateWithin(jail, inside));

        Path outside = jail.getParent().resolve("outside.txt");
        assertThrows(SecurityException.class, () -> PathSandbox.validateWithin(jail, outside));
    }

    @Test
    void acceptsValidZipEntries() throws Exception {
        assertDoesNotThrow(() -> PathSandbox.assertSafeZipEntry("word/document.xml"));
        assertDoesNotThrow(() -> PathSandbox.assertSafeZipEntry("xl/worksheets/sheet1.xml"));
        assertDoesNotThrow(() -> PathSandbox.assertSafeZipEntry("ppt/slides/slide1.xml"));
    }

    @Test
    void blocksZipSlipTraversalEntries() {
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("../../etc/passwd"));
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("..\\..\\windows\\system32\\cmd.exe"));
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("word/../../evil.exe"));
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("/root/pwned"));
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("C:\\Autoexec.bat"));
    }

    @Test
    void blocksNullBytesInZipEntries() {
        assertThrows(IOException.class, () -> PathSandbox.assertSafeZipEntry("word/document.xml\0evil.exe"));
    }
}
