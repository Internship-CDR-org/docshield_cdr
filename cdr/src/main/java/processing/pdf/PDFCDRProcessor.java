package processing.pdf;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import processing.common.CDRFileUtil;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import processing.common.CDRConsoleReporter;
import sanitization.pdf.PDFThreatSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.pdf.PDFThreatAnalyzer;
import validation.pdf.PDFIntegrityValidator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * PDF Content Disarm and Reconstruction processor.
 *
 * The input PDF is never overwritten. PDFBox loads the source object graph,
 * the PDF sanitizer removes active/embedded threat surfaces, and the complete
 * remaining object graph is written as a new PDF. The new PDF is then loaded
 * again and re-analyzed before the result is considered safe.
 */
public final class PDFCDRProcessor implements CDRProcessor {

    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        PDFThreatAnalyzer analyzer = new PDFThreatAnalyzer();
        PDFThreatSanitizer sanitizer = new PDFThreatSanitizer();
        final String inputSha256 = CDRFileUtil.sha256(inputFile);

        if (!Files.isRegularFile(inputFile)) {
            throw new java.io.IOException("PDF input is not a regular file.");
        }
        long inputSize = Files.size(inputFile);
        if (inputSize > threat.pdf.PDFSecurityPolicy.MAX_INPUT_BYTES) {
            throw new java.io.IOException("PDF exceeds the maximum safe input size of "
                    + (threat.pdf.PDFSecurityPolicy.MAX_INPUT_BYTES / (1024 * 1024)) + " MB.");
        }

        List<SecurityFinding> findings;
        List<String> actions;

        try (PDDocument document = Loader.loadPDF(inputFile.toFile())) {
            if (document.getNumberOfPages() <= 0) {
                throw new java.io.IOException("PDF contains no usable pages.");
            }
            if (document.getNumberOfPages() > threat.pdf.PDFSecurityPolicy.MAX_PAGES) {
                throw new java.io.IOException("PDF exceeds the maximum safe page limit of "
                        + threat.pdf.PDFSecurityPolicy.MAX_PAGES + ".");
            }
            findings = new ArrayList<>(analyzer.analyze(document));

            // Inspect embedded document bytes before the outer sanitizer removes the
            // attachment boundary. Unsupported or unsafe nested content is fail-closed.
            List<SecurityFinding> embeddedFindings = new threat.pdf.PDFEmbeddedPayloadInspector().inspect(document);
            findings.addAll(embeddedFindings);

            CDRConsoleReporter.printAnalyzerFindings("PDF", findings);
            if (!containsBlockingFinding(findings)) {
                CDRFileUtil.copyOriginal(inputFile, outputFile);
                String outputSha256 = CDRFileUtil.sha256(outputFile);
                if (!inputSha256.equals(outputSha256)) {
                    throw new java.io.IOException("Clean PDF copy failed byte-for-byte SHA-256 identity verification.");
                }
                actions = new ArrayList<>();
                actions.add("Input verified clean; original PDF copied without reconstruction.");
                return new CDRResult(findings, actions, outputFile, false, true, true,
                        new ArrayList<>(), inputSha256, outputSha256, true);
            }
            actions = new ArrayList<>(sanitizer.sanitize(document, findings));

            Path normalizedOutput = outputFile.toAbsolutePath().normalize();
            Path parent = normalizedOutput.getParent();
            if (parent != null) Files.createDirectories(parent);
            // Save to a temporary file in the destination directory first. This
            // prevents a failed PDF serialization from leaving a partial file
            // at the user-visible output path. The final move happens only after
            // PDFBox successfully completes the full write.
            Path tempOutput = Files.createTempFile(parent == null ? Path.of(".") : parent,
                    ".docshield-pdf-", ".tmp");
            try {
                document.setAllSecurityToBeRemoved(true);
                document.save(tempOutput.toFile());
                Files.move(tempOutput, normalizedOutput,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
                Files.move(tempOutput, normalizedOutput,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tempOutput);
            }
        }

        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;
        List<SecurityFinding> finalFindings = new ArrayList<>();

        if (reconstructed) {
            try (PDDocument reread = Loader.loadPDF(outputFile.toFile())) {
                integrityPassed = new PDFIntegrityValidator().validate(reread);
                finalFindings.addAll(analyzer.analyze(reread));
                finalFindings.addAll(new threat.pdf.PDFEmbeddedPayloadInspector().inspect(reread));
                finalFindings.addAll(new threat.pdf.PDFSecuritySurfaceVerifier().verify(reread));
                threatsRemoved = !containsBlockingFinding(finalFindings);
                if (!finalFindings.isEmpty()) {
                    actions.add("Post-reconstruction security verification found remaining PDF findings.");
                }
            }
        }
        CDRConsoleReporter.printFinalFindings("PDF", finalFindings);

        String outputSha256 = reconstructed ? CDRFileUtil.sha256(outputFile) : null;
        return new CDRResult(findings, actions, outputFile, reconstructed,
                integrityPassed, threatsRemoved, finalFindings, inputSha256, outputSha256, false);
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) {
            if (finding != null &&
                    (finding.getClassification() == FindingClassification.THREAT ||
                     finding.getClassification() == FindingClassification.POLICY_VIOLATION ||
                     finding.getClassification() == FindingClassification.SUSPICIOUS)) {
                return true;
            }
        }
        return false;
    }
}
