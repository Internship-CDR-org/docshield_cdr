package processing.docx;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import sanitization.docx.DOCXThreatSanitizer;
import sanitization.common.RecursiveOOXMLSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.docx.DOCXThreatAnalyzer;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import validation.ooxml.OOXMLIntegrityValidator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class DOCXCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        OOXMLPackageReader reader = new OOXMLPackageReader();
        OOXMLPackage packageData = reader.read(inputFile);

        DOCXThreatAnalyzer analyzer = new DOCXThreatAnalyzer();
        List<SecurityFinding> findings = analyzer.analyze(packageData);

        DOCXThreatSanitizer sanitizer = new DOCXThreatSanitizer();
        List<String> actions = new java.util.ArrayList<>(sanitizer.sanitize(packageData, findings));

        // Embedded OOXML is a nested trust boundary. Apply the same CDR
        // pipeline to a nested DOCX/XLSX/PPTX rather than trusting it merely
        // because it is inside an otherwise valid DOCX.
        RecursiveOOXMLSanitizer recursive = new RecursiveOOXMLSanitizer();
        RecursiveOOXMLSanitizer.Result recursiveResult =
                recursive.sanitizeEmbeddedPackages(packageData, findings);
        actions.addAll(recursiveResult.getActions());

        new OOXMLPackageWriter().write(packageData, outputFile);

        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;

        if (reconstructed) {
            OOXMLPackage reread = reader.read(outputFile);
            integrityPassed = new OOXMLIntegrityValidator().validate(reread);
            List<SecurityFinding> remaining = analyzer.analyze(reread);
            boolean embeddedSafe = !recursive.hasBlockingEmbeddedContent(reread);
            threatsRemoved = !containsBlockingFinding(remaining) && embeddedSafe;
        }

        return new CDRResult(findings, actions, outputFile, reconstructed,
                integrityPassed, threatsRemoved);
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) {
            if (finding == null) continue;
            if (finding.getClassification() == FindingClassification.THREAT ||
                    finding.getClassification() == FindingClassification.POLICY_VIOLATION) {
                return true;
            }
        }
        return false;
    }
}
