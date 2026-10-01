package sanitization.pptx;

import model.ooxml.OOXMLPackage;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;

import java.util.List;

/** PPTX entry point backed by the common OOXML sanitizer. */
public class PPTXThreatSanitizer {
    private final OOXMLThreatSanitizer delegate = new OOXMLThreatSanitizer();

    public List<String> sanitize(OOXMLPackage packageData, List<SecurityFinding> findings) {
        return delegate.sanitize(packageData, findings);
    }
}
