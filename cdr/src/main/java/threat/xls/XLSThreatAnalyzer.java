package threat.xls;

import threat.common.SecurityFinding;
import threat.legacy.LegacyOfficeThreatAnalyzer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class XLSThreatAnalyzer {
    public List<SecurityFinding> analyze(Path inputFile) throws IOException {
        return new LegacyOfficeThreatAnalyzer().analyze(inputFile, "XLS");
    }
}
