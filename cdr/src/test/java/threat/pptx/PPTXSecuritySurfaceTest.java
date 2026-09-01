package threat.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import org.junit.jupiter.api.Test;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security regression coverage for PresentationML surfaces that must share
 * the common OOXML threat model. These tests intentionally use structures,
 * not antivirus vendor names/signatures.
 */
class PPTXSecuritySurfaceTest {

    private OOXMLPackage packageWithXml(String xml) {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("ppt/slides/slide1.xml", "application/xml", xml.getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart("[Content_Types].xml", "application/xml", "<Types/>".getBytes(StandardCharsets.UTF_8)));
        return pkg;
    }

    @Test
    void detectsDanglingRelationshipReferenceAndRemovesIt() {
        OOXMLPackage pkg = packageWithXml(
                "<p:sld xmlns:p=\"p\" xmlns:a=\"a\" xmlns:r=\"r\"><a:blip r:embed=\"rMissing\"/></p:sld>");

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.INVALID_RELATIONSHIP));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        String xml = new String(pkg.getPart("ppt/slides/slide1.xml").getData(), StandardCharsets.UTF_8);
        assertFalse(xml.contains("rMissing"));
    }

    @Test
    void detectsExternalPptxActiveRelationshipTypes() {
        OOXMLPackage pkg = packageWithXml("<p:sld xmlns:p=\"p\"/>");
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rExt",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/media",
                "https://example.test/media.mp4", "External"));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXTERNAL_RESOURCE));
        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        assertTrue(pkg.getRelationships().stream().noneMatch(r -> "rExt".equals(r.getId())));
    }

    @Test
    void preservesNormalExternalHyperlink() {
        OOXMLPackage pkg = packageWithXml(
                "<p:sld xmlns:p=\"p\" xmlns:a=\"a\" xmlns:r=\"r\"><a:hlinkClick r:id=\"rWeb\"/></p:sld>");
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rWeb",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://example.com", "External"));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        assertTrue(pkg.getRelationships().stream().anyMatch(r -> "rWeb".equals(r.getId())));
    }

    @Test
    void detectsProgramMacroAndOleActionsInAnyPptPart() {
        String xml = "<p:timing xmlns:p=\"p\" xmlns:a=\"a\"><a:hlinkClick action=\"ppaction://program\"/><a:hlinkHover actionType=\"runmacro\"/><a:hlinkClick action=\"ppaction://ole?verb=0\"/></p:timing>";
        OOXMLPackage pkg = packageWithXml(xml);
        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().filter(f -> f.getType() == ThreatType.DANGEROUS_ACTION).count() >= 1);
        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        String cleaned = new String(pkg.getPart("ppt/slides/slide1.xml").getData(), StandardCharsets.UTF_8);
        assertFalse(cleaned.toLowerCase().contains("ppaction://program"));
        assertFalse(cleaned.toLowerCase().contains("runmacro"));
        assertFalse(cleaned.toLowerCase().contains("ppaction://ole"));
    }
    @Test
    void preservesObservedEmbeddedObjectWhenNoActiveThreatIsPresent() {
        OOXMLPackage pkg = packageWithXml("<p:sld xmlns:p=\"p\"/>");
        pkg.addPart(new OOXMLPart("ppt/embeddings/oleObject1.bin",
                "application/vnd.ms-office.oleObject", new byte[]{1,2,3}));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.OLE_OBJECT));
        assertTrue(findings.stream().allMatch(f -> f.getType() != ThreatType.OLE_OBJECT ||
                f.getClassification() == threat.common.FindingClassification.OBSERVATION));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        assertTrue(pkg.hasPart("ppt/embeddings/oleObject1.bin"));
    }

}
