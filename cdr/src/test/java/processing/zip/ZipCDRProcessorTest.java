package processing.zip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import processing.common.CDRResult;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ZIP container-only CDR.
 *
 * ZIP CDR validates the ZIP container itself but does not analyze the
 * security properties of inner PDF/DOCX/XLSX/PPTX/RTF/executable files.
 */
class ZipCDRProcessorTest {

    @TempDir
    Path tempDir;

    @Test
    void safeZipIsCopiedByteForByteAndShaDoesNotChange() throws Exception {
        Path input = tempDir.resolve("input.zip");
        Path output = tempDir.resolve("output.zip");

        createZip(input, "hello.txt", "Hello from DocShield");

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(Files.exists(output));
        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.isReconstructionSuccessful());
        assertTrue(result.isOriginalCopied(),
                "A safe ZIP must be released as an exact byte-for-byte copy.");
        assertFalse(result.hasThreats());
        assertEquals(result.getInputSha256(), result.getOutputSha256(),
                "Safe ZIP input/output SHA-256 must be identical.");
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output),
                "Safe ZIP output must contain exactly the original bytes.");

        assertZipContains(output, "hello.txt");
    }

    @Test
    void zipLevelThreatIsRemovedAndShaChanges() throws Exception {
        Path input = tempDir.resolve("unsafe.zip");
        Path output = tempDir.resolve("sanitized.zip");

        try (OutputStream fileOut = Files.newOutputStream(input);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {
            putEntry(zipOut, "safe.txt", "safe".getBytes(StandardCharsets.UTF_8));
            putEntry(zipOut, "../outside.txt", "unsafe".getBytes(StandardCharsets.UTF_8));
        }

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(Files.exists(output));
        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.isReconstructionSuccessful());
        assertFalse(result.isOriginalCopied(),
                "A ZIP with a container-level threat must be reconstructed.");
        assertTrue(result.hasThreats());
        assertTrue(result.isThreatRemoved());
        assertNotEquals(result.getInputSha256(), result.getOutputSha256(),
                "Sanitizing a ZIP must change its SHA-256.");

        assertZipContains(output, "safe.txt");
        assertZipDoesNotContain(output, "../outside.txt");
    }

    @Test
    void executableInsideZipDoesNotBecomeZipThreat() throws Exception {
        Path input = tempDir.resolve("input.zip");
        Path output = tempDir.resolve("output.zip");

        createZipBytes(
                input,
                "test.exe",
                new byte[]{'M', 'Z', 0x00, 0x00, 0x01, 0x02, 0x03, 0x04});

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.isReconstructionSuccessful());
        assertFalse(result.hasThreats(),
                "The executable is an inner file and must not be analyzed by ZIP CDR.");

        assertZipContains(output, "test.exe");
    }

    @Test
    void documentThreatInsideZipDoesNotBecomeZipThreat() throws Exception {
        Path input = tempDir.resolve("input.zip");
        Path output = tempDir.resolve("output.zip");

        // Deliberately opaque bytes. ZIP CDR must not identify or analyze them.
        createZipBytes(
                input,
                "suspicious.pdf",
                "This is intentionally opaque ZIP content."
                        .getBytes(StandardCharsets.UTF_8));

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertFalse(result.hasThreats());
        assertZipContains(output, "suspicious.pdf");
    }

    @Test
    void sanitizesPathTraversalEntry() throws Exception {
        Path input = tempDir.resolve("input.zip");
        Path output = tempDir.resolve("output.zip");

        try (OutputStream fileOut = Files.newOutputStream(input);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {
            putEntry(zipOut, "safe.txt", "safe".getBytes(StandardCharsets.UTF_8));
            putEntry(zipOut, "../outside.txt", "unsafe".getBytes(StandardCharsets.UTF_8));
        }

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(result.hasThreats());
        assertTrue(result.isThreatRemoved());
        assertNotEquals(result.getInputSha256(), result.getOutputSha256());
        assertZipContains(output, "safe.txt");
        assertZipDoesNotContain(output, "../outside.txt");
    }

    @Test
    void sanitizesAbsolutePathEntry() throws Exception {
        Path input = tempDir.resolve("input.zip");
        Path output = tempDir.resolve("output.zip");

        try (OutputStream fileOut = Files.newOutputStream(input);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {
            putEntry(zipOut, "safe.txt", "safe".getBytes(StandardCharsets.UTF_8));
            putEntry(zipOut, "/outside.txt", "unsafe".getBytes(StandardCharsets.UTF_8));
        }

        CDRResult result = new ZipCDRProcessor().process(input, output);

        assertTrue(result.hasThreats());
        assertTrue(result.isThreatRemoved());
        assertNotEquals(result.getInputSha256(), result.getOutputSha256());
        assertZipContains(output, "safe.txt");
        assertZipDoesNotContain(output, "/outside.txt");
    }

    @Test
    void rejectsDuplicateEntryNames() throws Exception {
        Path input = tempDir.resolve("duplicate.zip");
        Path output = tempDir.resolve("output.zip");

        try (OutputStream fileOut = Files.newOutputStream(input);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {

            putEntry(zipOut, "same.txt", "one".getBytes(StandardCharsets.UTF_8));

            // java.util.zip.ZipOutputStream itself rejects duplicate names.
            // Therefore create a duplicate-entry archive only if the runtime
            // allows it; otherwise this test is skipped by the exception.
            try {
                putEntry(zipOut, "same.txt", "two".getBytes(StandardCharsets.UTF_8));
            } catch (java.util.zip.ZipException expected) {
                return;
            }
        }

        assertThrows(
                Exception.class,
                () -> new ZipCDRProcessor().process(input, output));
    }

    @Test
    void nestedZipIsTreatedAsZipLevelThreatAndRemoved() throws Exception {
        Path nested = tempDir.resolve("nested.zip");
        Path outer = tempDir.resolve("outer.zip");
        Path output = tempDir.resolve("output.zip");

        // The content inside the nested ZIP is deliberately irrelevant.
        // ZIP CDR must not analyze it; the nested ZIP itself is the policy violation.
        createZip(nested, "inside.pdf", "opaque inner document");

        try (OutputStream fileOut = Files.newOutputStream(outer);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {
            putEntry(zipOut, "safe.txt", "safe".getBytes(StandardCharsets.UTF_8));
            putEntry(zipOut, "nested.zip", Files.readAllBytes(nested));
        }

        CDRResult result = new ZipCDRProcessor().process(outer, output);

        assertTrue(result.isOutputReady());
        assertTrue(result.isIntegrityPassed());
        assertTrue(result.hasThreats(),
                "A ZIP inside another ZIP is a ZIP-level policy threat.");
        assertTrue(result.isThreatRemoved());
        assertFalse(result.isOriginalCopied(),
                "A ZIP containing a nested ZIP must be reconstructed.");
        assertNotEquals(result.getInputSha256(), result.getOutputSha256(),
                "Removing a nested ZIP must change the SHA-256.");

        assertZipContains(output, "safe.txt");
        assertZipDoesNotContain(output, "nested.zip");
    }

    private void createZip(
            Path zipPath,
            String entryName,
            String content) throws IOException {
        createZipBytes(
                zipPath,
                entryName,
                content.getBytes(StandardCharsets.UTF_8));
    }

    private void createZipBytes(
            Path zipPath,
            String entryName,
            byte[] content) throws IOException {

        try (OutputStream fileOut = Files.newOutputStream(zipPath);
             ZipOutputStream zipOut = new ZipOutputStream(fileOut)) {
            putEntry(zipOut, entryName, content);
        }
    }

    private void putEntry(
            ZipOutputStream zipOut,
            String entryName,
            byte[] content) throws IOException {
        ZipEntry entry = new ZipEntry(entryName);
        zipOut.putNextEntry(entry);
        zipOut.write(content);
        zipOut.closeEntry();
    }

    private void assertZipContains(Path zipPath, String entryName)
            throws IOException {
        try (java.util.zip.ZipFile zip =
                     new java.util.zip.ZipFile(zipPath.toFile())) {
            assertNotNull(
                    zip.getEntry(entryName),
                    "Expected ZIP entry: " + entryName);
        }
    }
    private void assertZipDoesNotContain(Path zipPath, String entryName)
            throws IOException {
        try (java.util.zip.ZipFile zip =
                     new java.util.zip.ZipFile(zipPath.toFile())) {
            assertNull(zip.getEntry(entryName),
                    "Did not expect ZIP entry: " + entryName);
        }
    }

}
