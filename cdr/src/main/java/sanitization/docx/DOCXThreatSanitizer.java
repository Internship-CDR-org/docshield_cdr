package sanitization.docx;

import model.ooxml.OOXMLPackage;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;

import java.util.List;

/** DOCX entry point backed by the common OOXML sanitizer. */
public class DOCXThreatSanitizer {
    private final OOXMLThreatSanitizer delegate = new OOXMLThreatSanitizer();

    public List<String> sanitize(OOXMLPackage packageData, List<SecurityFinding> findings) {
        return delegate.sanitize(packageData, findings);
    }
}
