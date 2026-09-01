package threat.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import threat.ooxml.OOXMLThreatAnalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * PowerPoint-specific extension point for the common OOXML threat analyzer.
 *
 * Package-wide capabilities are detected by {@link OOXMLThreatAnalyzer}.
 * This class adds PresentationML-only package semantics that do not belong in
 * the generic package analyzer.
 */
public final class PPTXThreatAnalyzer {

    private final OOXMLThreatAnalyzer commonAnalyzer = new OOXMLThreatAnalyzer();

    public List<SecurityFinding> analyze(OOXMLPackage packageData) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (packageData == null) return findings;

        findings.addAll(commonAnalyzer.analyze(packageData));

        // Inspect OLE compound files inside PPTX embeddings. Presence of an
        // OLE object is only an observation; active OLE content (for example
        // VBA streams) is promoted to a real threat finding.
        findings.addAll(new OLEAnalyzer().analyze(packageData));

        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null) continue;

            String name = part.getPartName().toLowerCase(Locale.ROOT);
            String contentType = part.getContentType() == null
                    ? ""
                    : part.getContentType().toLowerCase(Locale.ROOT);

            // PowerPoint keeps ActiveX control persistence in ctrlProps as a
            // separate part. It must be disarmed with the control itself.
            if (name.startsWith("ppt/ctrlprops/")) {
                findings.add(new SecurityFinding(
                        FindingClassification.THREAT,
                        ThreatType.ACTIVEX_OBJECT,
                        ThreatSeverity.HIGH,
                        part,
                        null,
                        null,
                        "PowerPoint control-persistence part: " + name,
                        "The presentation contains ActiveX control persistence data.",
                        "Remove the control-persistence part together with the ActiveX control."
                ));
            }
        }

        return findings;
    }
}
