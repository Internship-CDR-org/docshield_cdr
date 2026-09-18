package threat.ppt;

import threat.common.SecurityFinding;
import threat.legacy.LegacyOfficeThreatAnalyzer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class PPTThreatAnalyzer {
    public List<SecurityFinding> analyze(Path inputFile) throws IOException {
        return new LegacyOfficeThreatAnalyzer().analyze(inputFile, "PPT");
    }
}
