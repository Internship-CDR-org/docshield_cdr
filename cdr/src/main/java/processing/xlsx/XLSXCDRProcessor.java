package processing.xlsx;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import sanitization.xlsx.XLSXThreatSanitizer;
import sanitization.common.RecursiveOOXMLSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.xlsx.XLSXThreatAnalyzer;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import validation.ooxml.OOXMLIntegrityValidator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class XLSXCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        OOXMLPackageReader reader = new OOXMLPackageReader();
        OOXMLPackage packageData = reader.read(inputFile);

        XLSXThreatAnalyzer analyzer = new XLSXThreatAnalyzer();
        List<SecurityFinding> findings = analyzer.analyze(packageData);

        XLSXThreatSanitizer sanitizer = new XLSXThreatSanitizer();
        List<String> actions = new java.util.ArrayList<>(sanitizer.sanitize(packageData, findings));

        // Embedded OOXML is a nested trust boundary. Apply the same CDR
        // engine recursively and use the format-specific analyzer selected
        // by the nested package's actual structure.
        RecursiveOOXMLSanitizer recursive = new RecursiveOOXMLSanitizer();
        List<SecurityFinding> recursiveFindings = new java.util.ArrayList<>();
        RecursiveOOXMLSanitizer.Result recursiveResult =
                recursive.sanitizeEmbeddedPackages(packageData, recursiveFindings);
        actions.addAll(recursiveResult.getActions());
        findings.addAll(recursiveFindings);

        new OOXMLPackageWriter().write(packageData, outputFile);

        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;
        if (reconstructed) {
            OOXMLPackage reread = reader.read(outputFile);
            integrityPassed = new OOXMLIntegrityValidator().validate(reread);
            threatsRemoved = !containsBlockingFinding(analyzer.analyze(reread))
                    && !recursive.hasBlockingEmbeddedContent(reread);
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
