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
import threat.pptx.Ole10NativeAnalyzer;
import threat.pptx.PayloadFingerprint;
import threat.pptx.PayloadIdentifier;
import threat.pptx.SecurityPolicy;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import validation.ooxml.OOXMLIntegrityValidator;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** PPTX CDR entry point. Package handling is fully shared with DOCX/XLSX. */
public class PPTXCDRProcessor implements CDRProcessor {
    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        OOXMLPackageReader reader = new OOXMLPackageReader();
        OOXMLPackage packageData = reader.read(inputFile);

        List<SecurityFinding> findings = new ArrayList<>();
        findings.addAll(new PPTXThreatAnalyzer().analyze(packageData));

        List<String> actions = new ArrayList<>();
        RecursiveOOXMLSanitizer recursiveSanitizer = new RecursiveOOXMLSanitizer();
        List<SecurityFinding> recursiveFindings = new ArrayList<>();
        RecursiveOOXMLSanitizer.Result recursiveResult =
                recursiveSanitizer.sanitizeEmbeddedPackages(packageData, recursiveFindings);
        actions.addAll(recursiveResult.getActions());

        // Nested findings describe the nested package that was inspected and
        // sanitized. They are deliberately added after the outer sanitizer has
        // run so a nested part name can never be mistaken for a top-level part.
        analyzeEmbeddedPayloads(packageData, findings);
        actions.addAll(new PPTXThreatSanitizer().sanitize(packageData, findings));
        findings.addAll(recursiveFindings);
        new OOXMLPackageWriter().write(packageData, outputFile);

        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;
        if (reconstructed) {
            OOXMLPackage reread = reader.read(outputFile);
            integrityPassed = new OOXMLIntegrityValidator().validate(reread);
            threatsRemoved = !containsBlockingFinding(new PPTXThreatAnalyzer().analyze(reread))
                    && !containsEmbeddedNativePayload(reread)
                    && !recursiveSanitizer.hasBlockingEmbeddedContent(reread);
        }

        return new CDRResult(findings, actions, outputFile, reconstructed,
                integrityPassed, threatsRemoved);
    }

    private void analyzeEmbeddedPayloads(OOXMLPackage packageData,
                                         List<SecurityFinding> findings) throws Exception {
        Ole10NativeAnalyzer nativeAnalyzer = new Ole10NativeAnalyzer();
        PayloadIdentifier identifier = new PayloadIdentifier();
        PayloadFingerprint fingerprint = new PayloadFingerprint();
        SecurityPolicy policy = new SecurityPolicy();

        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null ||
                    !part.getPartName().toLowerCase().contains("/embeddings/") ||
                    part.getData() == null || part.getData().length == 0) continue;

            try (POIFSFileSystem fs = new POIFSFileSystem(
                    new ByteArrayInputStream(part.getData()))) {
                DirectoryNode root = fs.getRoot();
                for (Ole10NativeAnalyzer.NativePayload payload : nativeAnalyzer.inspect(root)) {
                    if (payload == null) continue;
                    PayloadIdentifier.Identification id = identifier.identify(
                            payload.getFilename(), payload.getPayload());
                    PayloadFingerprint.Fingerprint fp = fingerprint.fingerprint(payload.getPayload());
                    findings.addAll(policy.evaluate(id, fp, part));
                }
            } catch (Exception ignored) {
                // The common analyzer has already classified the embedded boundary.
                // A non-OLE embedded object is not parsed as OLE here.
            }
        }
    }

    private boolean containsEmbeddedNativePayload(OOXMLPackage packageData) {
        if (packageData == null) return true;
        Ole10NativeAnalyzer analyzer = new Ole10NativeAnalyzer();
        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null || part.getData() == null ||
                    !part.getPartName().toLowerCase().contains("/embeddings/")) continue;
            try (POIFSFileSystem fs = new POIFSFileSystem(new ByteArrayInputStream(part.getData()))) {
                if (!analyzer.inspect(fs.getRoot()).isEmpty()) return true;
            } catch (Exception ignored) {
                // Not an OLE compound file; common package analysis covers it.
            }
        }
        return false;
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) {
            if (finding != null &&
                    (finding.getClassification() == FindingClassification.THREAT ||
                     finding.getClassification() == FindingClassification.POLICY_VIOLATION)) return true;
        }
        return false;
    }
}
