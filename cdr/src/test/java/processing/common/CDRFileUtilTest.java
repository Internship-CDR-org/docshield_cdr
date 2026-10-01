package processing.common;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CDRFileUtilTest {
    @Test
    void copyOriginalPreservesExactBytesAndSha256() throws Exception {
        Path input = Files.createTempFile("docshield-sha-input-", ".bin");
        Path output = Files.createTempFile("docshield-sha-output-", ".bin");
        try {
            Files.write(input, "DocShield SHA-256 identity test\n".getBytes(StandardCharsets.UTF_8));
            String before = CDRFileUtil.sha256(input);
            CDRFileUtil.copyOriginal(input, output);
            assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
            assertEquals(before, CDRFileUtil.sha256(output));
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(output);
        }
    }
}
