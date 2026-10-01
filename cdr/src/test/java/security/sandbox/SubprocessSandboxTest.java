package security.sandbox;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SubprocessSandboxTest {

    @TempDir
    Path temp;

    @Test
    void verifiesBwrapAvailabilityAndCommandWrapping() {
        boolean available = SubprocessSandbox.isBwrapAvailable();
        List<String> rawCommand = List.of("echo", "test");
        List<String> wrapped = SubprocessSandbox.buildSandboxedCommand(rawCommand, temp, null);

        assertNotNull(wrapped);
        if (available) {
            assertEquals("bwrap", wrapped.get(0));
            assertTrue(wrapped.contains("--unshare-all"));
            assertTrue(wrapped.contains("--die-with-parent"));
        } else {
            assertEquals("echo", wrapped.get(0));
        }
    }

    @Test
    void executesSimpleSubprocessSuccessfully() throws Exception {
        Path script = temp.resolve("test-echo.sh");
        Files.writeString(script, "#!/usr/bin/env bash\necho 'sandbox-success'\n");
        assertTrue(script.toFile().setExecutable(true));

        SubprocessSandbox.SubprocessResult result = SubprocessSandbox.execute(
                List.of(script.toAbsolutePath().toString()),
                temp,
                null,
                null,
                5,
                1024 * 1024,
                "timeout",
                "limit"
        );

        assertEquals(0, result.exitCode());
        assertTrue(result.diagnostics().contains("sandbox-success"));
    }

    @Test
    void terminatesWhenProcessTimesOut() throws Exception {
        Path script = temp.resolve("test-sleep.sh");
        Files.writeString(script, "#!/usr/bin/env bash\nsleep 10\n");
        assertTrue(script.toFile().setExecutable(true));

        IOException error = assertThrows(IOException.class, () ->
                SubprocessSandbox.execute(
                        List.of(script.toAbsolutePath().toString()),
                        temp,
                        null,
                        null,
                        1,
                        1024 * 1024,
                        "custom timed out error",
                        "limit"
                )
        );

        assertTrue(error.getMessage().contains("custom timed out error"));
    }
}
