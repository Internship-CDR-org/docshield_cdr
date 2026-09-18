package processing.xlsx;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import sanitization.xlsx.XLSXThreatSanitizer;
import sanitization.common.RecursiveOOXMLSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.xlsx.XLSXThreatAnalyzer;
import processing.common.CDRConsoleReporter;
import processing.common.CDRFileUtil;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import validation.ooxml.OOXMLIntegrityValidator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XLSXCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        return process(inputFile, outputFile, true);
    }

    /** Internal variant used by legacy-format adapters to avoid duplicate console output. */
    public CDRResult process(Path inputFile, Path outputFile, boolean printConsoleFindings) throws Exception {
        OOXMLPackageReader reader = new OOXMLPackageReader();
        final String inputSha256 = processing.common.CDRFileUtil.sha256(inputFile);
        OOXMLPackage packageData = reader.read(inputFile);
        XLSXThreatAnalyzer analyzer = new XLSXThreatAnalyzer();
        List<SecurityFinding> findings = analyzer.analyze(packageData);
        if (printConsoleFindings) CDRConsoleReporter.printAnalyzerFindings("XLSX", findings);

        XLSXThreatSanitizer sanitizer = new XLSXThreatSanitizer();
        List<String> actions = new ArrayList<>(sanitizer.sanitize(packageData, findings));
        RecursiveOOXMLSanitizer recursive = new RecursiveOOXMLSanitizer();
        List<SecurityFinding> recursiveFindings = new ArrayList<>();
        RecursiveOOXMLSanitizer.Result recursiveResult = recursive.sanitizeEmbeddedPackages(packageData, recursiveFindings);
        actions.addAll(recursiveResult.getActions());
        findings.addAll(recursiveFindings);

        if (!containsBlockingFinding(findings)) {
            CDRFileUtil.copyOriginal(inputFile, outputFile);
            String outputSha256 = CDRFileUtil.sha256(outputFile);
            if (!inputSha256.equals(outputSha256)) throw new java.io.IOException("Clean XLSX copy failed SHA-256 identity verification.");
            actions.add("Input verified clean; original XLSX copied without reconstruction.");
            return new CDRResult(findings, actions, outputFile, false, true, true,
                    new ArrayList<>(), inputSha256, outputSha256, true);
        }

        new OOXMLPackageWriter().write(packageData, outputFile);
        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        List<SecurityFinding> finalFindings = new ArrayList<>();
        boolean threatsRemoved = false;

        // Bounded post-reconstruction hardening loop. A first sanitization can
        // expose a second-layer relationship/embedded-content finding only
        // after the package has been rewritten and reread. Re-sanitize at most
        // three times, then fail closed if anything blocking remains.
        for (int pass = 1; reconstructed && pass <= 3; pass++) {
            OOXMLPackage reread = reader.read(outputFile);
            integrityPassed = new OOXMLIntegrityValidator().validate(reread);
            finalFindings = new ArrayList<>();
            finalFindings.addAll(analyzer.analyze(reread));
            boolean embeddedSafe = !recursive.hasBlockingEmbeddedContent(reread);
            threatsRemoved = integrityPassed && !containsBlockingFinding(finalFindings) && embeddedSafe;
            if (threatsRemoved) break;

            if (pass < 3 && containsBlockingFinding(finalFindings)) {
                List<String> retryActions = new XLSXThreatSanitizer().sanitize(reread, finalFindings);
                actions.addAll(retryActions);
                RecursiveOOXMLSanitizer.Result retryRecursive = recursive.sanitizeEmbeddedPackages(reread, finalFindings);
                actions.addAll(retryRecursive.getActions());
                new OOXMLPackageWriter().write(reread, outputFile);
            }
        }
        if (printConsoleFindings) CDRConsoleReporter.printFinalFindings("XLSX", finalFindings);
        if (!finalFindings.isEmpty()) actions.add("Post-reconstruction security verification found remaining blocking or policy findings.");
        String outputSha256 = reconstructed ? CDRFileUtil.sha256(outputFile) : null;
        return new CDRResult(findings, actions, outputFile, reconstructed, integrityPassed, threatsRemoved, finalFindings, inputSha256, outputSha256, false);
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) if (finding != null && (finding.getClassification() == FindingClassification.THREAT || finding.getClassification() == FindingClassification.POLICY_VIOLATION || finding.getClassification() == FindingClassification.SUSPICIOUS)) return true;
        return false;
    }
}
