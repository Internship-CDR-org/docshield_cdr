package threat.doc;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Structural, non-executing analyzer for legacy binary Word documents. */
public final class DOCThreatAnalyzer {
    public List<SecurityFinding> analyze(Path inputFile) throws IOException {
        List<SecurityFinding> findings = new ArrayList<>();
        try (POIFSFileSystem fs = new POIFSFileSystem(inputFile.toFile())) {
            scan(fs.getRoot(), "", findings);
        } catch (IOException e) {
            throw new IOException("Legacy DOC security inspection failed: " + e.getMessage(), e);
        }
        return findings;
    }

    private void scan(DirectoryNode directory, String parentPath,
                      List<SecurityFinding> findings) throws IOException {
        for (Entry entry : directory) {
            if (entry == null) continue;
            String name = entry.getName();
            String current = parentPath.isEmpty() ? name : parentPath + "/" + name;
            String lower = name.toLowerCase(Locale.ROOT);

            if (entry instanceof DirectoryNode child) {
                if (isVbaStorage(lower)) {
                    findings.add(new SecurityFinding(
                            FindingClassification.THREAT, ThreatType.VBA_PROJECT, ThreatSeverity.HIGH,
                            null, current, null,
                            "Legacy DOC VBA storage detected at " + current,
                            "The binary Word document contains a VBA macro project in its OLE storage tree.",
                            "Remove the macro-bearing content during DOC-to-DOCX CDR conversion."));
                }
                scan(child, current, findings);
            } else if (isVbaStream(lower, parentPath) && !containsVbaFinding(findings)) {
                findings.add(new SecurityFinding(
                        FindingClassification.THREAT, ThreatType.VBA_PROJECT, ThreatSeverity.HIGH,
                        null, current, null,
                        "Legacy DOC VBA stream detected at " + current,
                        "The binary Word document contains a VBA macro stream.",
                        "Remove the macro-bearing content during DOC-to-DOCX CDR conversion."));
            }
        }
    }

    private boolean isVbaStorage(String name) {
        return "vba".equals(name) || "macros".equals(name)
                || "_vba_project".equals(name) || name.contains("vba_project");
    }

    private boolean isVbaStream(String name, String parentPath) {
        String parent = parentPath == null ? "" : parentPath.toLowerCase(Locale.ROOT);
        return ("dir".equals(name) || "project".equals(name) || "projectwm".equals(name)
                || "_vba_project".equals(name)) && (parent.contains("vba") || parent.contains("macro"));
    }

    private boolean containsVbaFinding(List<SecurityFinding> findings) {
        for (SecurityFinding finding : findings) {
            if (finding != null && finding.getType() == ThreatType.VBA_PROJECT) return true;
        }
        return false;
    }
}
