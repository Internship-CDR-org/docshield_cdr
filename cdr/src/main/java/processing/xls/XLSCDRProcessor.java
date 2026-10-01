package processing.xls;

import processing.common.CDRConsoleReporter;
import processing.xlsx.XLSXCDRProcessor;
import processing.common.CDRProcessor;
import processing.common.CDRFileUtil;
import processing.common.CDRResult;
import parsing.xls.XLSToXLSXConverter;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.xls.XLSThreatAnalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** CDR processor for legacy binary XLS files. */
public final class XLSCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        List<SecurityFinding> originalFindings = new XLSThreatAnalyzer().analyze(inputFile);
        CDRConsoleReporter.printAnalyzerFindings("XLS", originalFindings);

        Path convertedFile = null;
        try {
            convertedFile = new XLSToXLSXConverter().convert(inputFile);
            System.out.println("DocShield: XLS → XLSX conversion successful.");
            System.out.println("DocShield: Converted XLSX is ready for CDR sanitization and reconstruction.");

            List<String> actions = new ArrayList<>();
            for (SecurityFinding f : originalFindings) {
                if (f != null && f.getClassification() != FindingClassification.OBSERVATION) {
                    actions.add("Disarmed legacy XLS content during isolated XLS → XLSX conversion: "
                            + f.getType() + (f.getDescription() == null ? "" : " (" + f.getDescription() + ")"));
                }
            }

            CDRResult modern = new XLSXCDRProcessor().process(convertedFile, outputFile, false);
            List<SecurityFinding> finalFindings = new ArrayList<>(modern.getFinalFindings());
            CDRConsoleReporter.printFinalFindings("XLS", finalFindings);
            actions.addAll(modern.getActions());

            if (!modern.isOutputReady()) throw new IOException("XLSX CDR did not produce a usable output after successful XLS → XLSX conversion.");
            if (!modern.isIntegrityPassed()) throw new IOException("XLSX CDR integrity validation failed after successful XLS → XLSX conversion.");
            if (containsBlocking(finalFindings)) throw new IOException("A security finding remained after XLS → XLSX conversion and CDR reconstruction.");

            System.out.println("DocShield: XLS sanitization and reconstruction successful.");
            return new CDRResult(originalFindings, actions, outputFile, true, true,
                    !containsBlocking(finalFindings) && modern.isThreatRemoved(), finalFindings,
                    CDRFileUtil.sha256(inputFile), CDRFileUtil.sha256(outputFile), false);
        } finally {
            deleteConvertedWorkspace(convertedFile);
        }
    }

    private static void deleteConvertedWorkspace(Path convertedFile) {
        if (convertedFile == null || convertedFile.getParent() == null) return;
        Path workspace = convertedFile.getParent().getParent();
        if (workspace == null || !Files.exists(workspace)) return;
        try (var paths = Files.walk(workspace)) {
            paths.sorted((a,b) -> Integer.compare(b.getNameCount(), a.getNameCount())).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (IOException e) {
                    System.err.println("DocShield: Could not remove temporary conversion artifact: " + path + " (" + e.getMessage() + ")");
                }
            });
        } catch (IOException e) {
            System.err.println("DocShield: Could not remove temporary LibreOffice workspace: " + workspace + " (" + e.getMessage() + ")");
        }
    }
    private static boolean containsBlocking(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding f : findings) if (f != null && (f.getClassification()==FindingClassification.THREAT || f.getClassification()==FindingClassification.POLICY_VIOLATION || f.getClassification()==FindingClassification.SUSPICIOUS)) return true;
        return false;
    }
}
