package sanitization.common;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import org.junit.jupiter.api.Test;
import threat.common.SecurityFinding;
import threat.ooxml.OOXMLThreatAnalyzer;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OOXMLThreatSanitizerTest {
    @Test
    void removesUnsafePartsRelationshipsAndContentTypes() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("ppt/slides/slide1.xml", "application/xml", "<p/>".getBytes()));
        pkg.addPart(new OOXMLPart("ppt/embeddings/evil.bin", "application/vnd.ms-office.oleObject", new byte[]{'M','Z'}));
        pkg.addContentType("ppt/embeddings/evil.bin", "application/vnd.ms-office.oleObject");
        pkg.addRelationship(new OOXMLRelationship("ppt/slides/slide1.xml", "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
                "../embeddings/evil.bin", null));

        List<SecurityFinding> findings = new OOXMLThreatAnalyzer().analyze(pkg);
        List<String> actions = new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertFalse(pkg.hasPart("ppt/embeddings/evil.bin"));
        assertEquals(0, pkg.getRelationships().size());
        assertNull(pkg.getContentType("ppt/embeddings/evil.bin"));
        assertFalse(actions.isEmpty());
    }

    @Test
    void preservesOrdinaryExternalHyperlinks() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("word/document.xml", "application/xml", "<d/>".getBytes()));
        pkg.addRelationship(new OOXMLRelationship("word/document.xml", "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://example.com", "External"));

        List<SecurityFinding> findings = new OOXMLThreatAnalyzer().analyze(pkg);
        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertEquals(1, pkg.getRelationships().size());
    }
}
