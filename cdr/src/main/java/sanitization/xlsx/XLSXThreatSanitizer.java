package sanitization.xlsx;

import model.ooxml.OOXMLPackage;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;

import java.util.List;

/** XLSX entry point backed by the common OOXML sanitizer. */
public class XLSXThreatSanitizer {
    private final OOXMLThreatSanitizer delegate = new OOXMLThreatSanitizer();

    public List<String> sanitize(OOXMLPackage packageData, List<SecurityFinding> findings) {
        return delegate.sanitize(packageData, findings);
    }
}
