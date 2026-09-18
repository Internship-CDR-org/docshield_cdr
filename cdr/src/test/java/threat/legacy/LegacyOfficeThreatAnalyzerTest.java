package threat.legacy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import threat.common.ThreatType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LegacyOfficeThreatAnalyzerTest {
    @TempDir Path temp;

    @Test
    void detectsLegacyXlsVbaAndCommandIndicators() throws Exception {
        Path xls = temp.resolve("macro.xls");
        Files.write(xls, "_VBA_PROJECT_CUR\nPROJECTwm\npowershell.exe -EncodedCommand test".getBytes());
        List<?> findings = new LegacyOfficeThreatAnalyzer().analyze(xls, "XLS");
        assertTrue(findings.stream().anyMatch(f -> ((threat.common.SecurityFinding) f).getType() == ThreatType.EXECUTABLE_PAYLOAD));
    }

    @Test
    void detectsLegacyXlsCommandPipeDdeFormulaIndicator() throws Exception {
        Path xls = temp.resolve("dde.xls");
        Files.write(xls, "cmd|/C powershell.exe -NoExit -e AAA!A0".getBytes());
        List<?> findings = new LegacyOfficeThreatAnalyzer().analyze(xls, "XLS");
        assertTrue(findings.stream().anyMatch(f -> ((threat.common.SecurityFinding) f).getType() == ThreatType.DDE));
    }

    @Test
    void detectsLegacyPptInteractiveActionRecord() throws Exception {
        Path ppt = temp.resolve("action.ppt");
        byte[] data = new byte[16];
        data[2] = (byte) 0xF3;
        data[3] = 0x0F;
        Files.write(ppt, data);
        List<?> findings = new LegacyOfficeThreatAnalyzer().analyze(ppt, "PPT");
        assertTrue(findings.stream().anyMatch(f -> ((threat.common.SecurityFinding) f).getType() == ThreatType.DANGEROUS_ACTION));
    }
}
