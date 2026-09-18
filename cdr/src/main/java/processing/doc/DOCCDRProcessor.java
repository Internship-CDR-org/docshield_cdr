package processing.doc;

import parsing.doc.DOCToDOCXConverter;
import processing.common.CDRConsoleReporter;
import processing.common.CDRProcessor;
import processing.common.CDRFileUtil;
import processing.common.CDRResult;
import processing.docx.DOCXCDRProcessor;
import threat.common.SecurityFinding;
import threat.doc.DOCThreatAnalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** CDR processor for legacy binary DOC files. */
public class DOCCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        // Inspect the legacy binary document BEFORE conversion. LibreOffice may
        // remove active content during conversion, so inspecting only the
        // resulting DOCX would incorrectly report the original threat as absent.
        List<SecurityFinding> originalFindings = new DOCThreatAnalyzer().analyze(inputFile);
        CDRConsoleReporter.printAnalyzerFindings("DOC", originalFindings);

        DOCToDOCXConverter converter = new DOCToDOCXConverter();
        Path convertedFile = null;
        try {
            convertedFile = converter.convert(inputFile);
            System.out.println("DocShield: DOC → DOCX conversion successful.");
            System.out.println("DocShield: Converted DOCX is ready for CDR sanitization and reconstruction.");

            List<String> conversionActions = new ArrayList<>();
            for (SecurityFinding finding : originalFindings) {
                if (finding != null && finding.getClassification() != null &&
                        finding.getClassification() != threat.common.FindingClassification.OBSERVATION) {
                    conversionActions.add("Disarmed legacy DOC content during isolated DOC → DOCX conversion: "
                            + finding.getType() + " at " + finding.getSourcePart());
                }
            }

            CDRResult docxResult = new DOCXCDRProcessor().process(convertedFile, outputFile, false);
            List<SecurityFinding> finalFindings = new ArrayList<>(docxResult.getFinalFindings());
            CDRConsoleReporter.printFinalFindings("DOC", finalFindings);

            List<String> actions = new ArrayList<>(conversionActions);
            actions.addAll(docxResult.getActions());

            if (!docxResult.isOutputReady()) {
                throw new IOException("DOCX CDR did not produce a usable output after successful DOC → DOCX conversion.");
            }
            if (!docxResult.isIntegrityPassed()) {
                throw new IOException("DOCX CDR integrity validation failed after successful DOC → DOCX conversion.");
            }
            if (docxResult.hasBlockingFindings() && !docxResult.isThreatRemoved()) {
                throw new IOException("A detected threat could not be completely removed after DOC → DOCX conversion.");
            }
            System.out.println("DocShield: DOC sanitization and reconstruction successful.");
            return new CDRResult(originalFindings, actions, outputFile, true, true,
                    !docxResult.hasBlockingFindings() && docxResult.isThreatRemoved(), finalFindings,
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
            paths.sorted((a, b) -> Integer.compare(b.getNameCount(), a.getNameCount()))
                    .forEach(path -> {
                        try { Files.deleteIfExists(path); }
                        catch (IOException cleanupError) {
                            System.err.println("DocShield: Could not remove temporary conversion artifact: "
                                    + path + " (" + cleanupError.getMessage() + ")");
                        }
                    });
        } catch (IOException cleanupError) {
            System.err.println("DocShield: Could not remove temporary LibreOffice workspace: "
                    + workspace + " (" + cleanupError.getMessage() + ")");
        }
    }
}
