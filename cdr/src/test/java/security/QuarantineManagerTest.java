package security;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class QuarantineManagerTest {
    @Test
    void createsQuarantineCopyAndEvidenceRecord() throws Exception {
        Path tempDir = Files.createTempDirectory("docshield-quarantine-test-");
        Path input = tempDir.resolve("threat sample.pdf");
        Files.writeString(input, "test-content");

        // The manager intentionally uses output/quarantine relative to the process,
        // so this test validates the returned artifact rather than assuming a custom root.
        Path quarantined = QuarantineManager.quarantine(input, "unsafe test\nreason");
        assertTrue(Files.isRegularFile(quarantined));
        assertTrue(quarantined.getFileName().toString().endsWith(".quarantined"));

        Path note = quarantined.resolveSibling(quarantined.getFileName() + ".txt");
        assertTrue(Files.isRegularFile(note));
        String report = Files.readString(note);
        assertTrue(report.contains("SHA-256:"));
        assertTrue(report.contains("Reason: unsafe test reason"));

        Files.deleteIfExists(note);
        Files.deleteIfExists(quarantined);
        Files.deleteIfExists(input);
        Files.deleteIfExists(tempDir);
    }
}
