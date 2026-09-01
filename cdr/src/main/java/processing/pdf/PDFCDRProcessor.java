package processing.pdf;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
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

            System.out.println("=== PDF ANALYZER FINDINGS: " + findings.size() + " ===");
            for (SecurityFinding f : findings) {
                System.out.println(
                    "PDF FINDING: " +
                    f.getClassification() + " | " +
                    f.getType() + " | " +
                    f.getDescription()
                );
            }
            // Inspect embedded document bytes before the outer sanitizer removes the
            // attachment boundary. Unsupported or unsafe nested content is fail-closed.
            List<SecurityFinding> embeddedFindings = new threat.pdf.PDFEmbeddedPayloadInspector().inspect(document);
            findings.addAll(embeddedFindings);

            System.out.println("=== PDF FINAL FINDINGS: " + findings.size() + " ===");
            for (SecurityFinding f : findings) {
                System.out.println(
                    "PDF FINAL FINDING: " +
                    f.getClassification() + " | " +
                    f.getType() + " | " +
                    f.getDescription()
                );
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

        if (reconstructed) {
            try (PDDocument reread = Loader.loadPDF(outputFile.toFile())) {
                integrityPassed = new PDFIntegrityValidator().validate(reread);
                List<SecurityFinding> remaining = new ArrayList<>(analyzer.analyze(reread));
                remaining.addAll(new threat.pdf.PDFEmbeddedPayloadInspector().inspect(reread));
                threatsRemoved = !containsBlockingFinding(remaining);
                if (!threatsRemoved) {
                    actions.add("Post-reconstruction security verification found remaining blocking PDF content.");
                }
            }
        }

        return new CDRResult(findings, actions, outputFile, reconstructed,
                integrityPassed, threatsRemoved);
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) {
            if (finding != null &&
                    (finding.getClassification() == FindingClassification.THREAT ||
                     finding.getClassification() == FindingClassification.POLICY_VIOLATION)) {
                return true;
            }
        }
        return false;
    }
}
