package processing.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import sanitization.pptx.PPTXThreatSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.pptx.PPTXThreatAnalyzer;
import sanitization.common.RecursiveOOXMLSanitizer;
import processing.common.CDRFileUtil;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import processing.common.CDRConsoleReporter;
import validation.ooxml.OOXMLIntegrityValidator;


import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** PPTX CDR entry point. Package handling is fully shared with DOCX/XLSX. */
public class PPTXCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        return process(inputFile, outputFile, true);
    }

    /** Internal variant used by legacy-format adapters to avoid duplicate console output. */
    public CDRResult process(Path inputFile, Path outputFile, boolean printConsoleFindings) throws Exception {
        OOXMLPackageReader reader = new OOXMLPackageReader();
        final String inputSha256 = processing.common.CDRFileUtil.sha256(inputFile);
        OOXMLPackage packageData = reader.read(inputFile);

        List<SecurityFinding> findings = new ArrayList<>();
        findings.addAll(new PPTXThreatAnalyzer().analyze(packageData));
        List<String> actions = new ArrayList<>();

        RecursiveOOXMLSanitizer recursiveSanitizer = new RecursiveOOXMLSanitizer();
        List<SecurityFinding> recursiveFindings = new ArrayList<>();
        RecursiveOOXMLSanitizer.Result recursiveResult =
                recursiveSanitizer.sanitizeEmbeddedPackages(packageData, recursiveFindings);
        actions.addAll(recursiveResult.getActions());
        findings.addAll(recursiveFindings);
        if (printConsoleFindings) CDRConsoleReporter.printAnalyzerFindings("PPTX", findings);

        if (!containsBlockingFinding(findings)) {
            CDRFileUtil.copyOriginal(inputFile, outputFile);
            String outputSha256 = CDRFileUtil.sha256(outputFile);
            if (!inputSha256.equals(outputSha256)) throw new java.io.IOException("Clean PPTX copy failed SHA-256 identity verification.");
            actions.add("Input verified clean; original PPTX copied without reconstruction.");
            return new CDRResult(findings, actions, outputFile, false, true, true,
                    new ArrayList<>(), inputSha256, outputSha256, true);
        }

        actions.addAll(new PPTXThreatSanitizer().sanitize(packageData, findings));
        new OOXMLPackageWriter().write(packageData, outputFile);
        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;
        List<SecurityFinding> finalFindings = new ArrayList<>();

        // Bounded post-reconstruction hardening loop. Re-read and re-analyze
        // after each rewrite so newly exposed package-graph findings can be
        // disarmed without immediately quarantining the document.
        for (int pass = 1; reconstructed && pass <= 3; pass++) {
            OOXMLPackage reread = reader.read(outputFile);
            integrityPassed = new OOXMLIntegrityValidator().validate(reread);
            finalFindings = new ArrayList<>();
            finalFindings.addAll(new PPTXThreatAnalyzer().analyze(reread));
            boolean embeddedSafe = !recursiveSanitizer.hasBlockingEmbeddedContent(reread);
            threatsRemoved = integrityPassed && !containsBlockingFinding(finalFindings) && embeddedSafe;
            if (threatsRemoved) break;

            if (pass < 3 && containsBlockingFinding(finalFindings)) {
                actions.addAll(new PPTXThreatSanitizer().sanitize(reread, finalFindings));
                RecursiveOOXMLSanitizer.Result retryRecursive =
                        recursiveSanitizer.sanitizeEmbeddedPackages(reread, finalFindings);
                actions.addAll(retryRecursive.getActions());
                new OOXMLPackageWriter().write(reread, outputFile);
            }
        }
        if (printConsoleFindings) CDRConsoleReporter.printFinalFindings("PPTX", finalFindings);
        if (!finalFindings.isEmpty()) actions.add("Post-reconstruction security verification found remaining PPTX findings.");

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
                     finding.getClassification() == FindingClassification.SUSPICIOUS)) return true;
        }
        return false;
    }
}
