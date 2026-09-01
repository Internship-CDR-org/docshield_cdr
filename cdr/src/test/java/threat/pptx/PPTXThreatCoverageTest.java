package threat.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import org.junit.jupiter.api.Test;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;
import threat.common.ThreatType;
import validation.ooxml.OOXMLIntegrityValidator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PPTXThreatCoverageTest {

    @Test
    void removesPowerPointProgramActionAndItsRelationship() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart(
                "ppt/slides/slide1.xml",
                "application/xml",
                ("<p:sld xmlns:p=\"p\" xmlns:a=\"a\" xmlns:r=\"r\">" +
                 "<a:hlinkClick r:id=\"rId7\" action=\"ppaction://program\"/>" +
                 "</p:sld>").getBytes(StandardCharsets.UTF_8)));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml",
                "rId7",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "file:///C:/Windows/System32/calc.exe",
                "External"));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.DANGEROUS_ACTION));
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.DANGEROUS_URI));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertTrue(pkg.getRelationships().isEmpty());
        String xml = new String(pkg.getPart("ppt/slides/slide1.xml").getData(), StandardCharsets.UTF_8);
        assertFalse(xml.toLowerCase().contains("ppaction://program"));
        assertFalse(xml.contains("rId7"));
    }

    @Test
    void removesVbaActiveXAndControlPersistence() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("ppt/presentation.xml", "application/xml", "<p:presentation/>".getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart("ppt/vbaProject.bin", "application/vnd.ms-office.vbaProject", new byte[]{1}));
        pkg.addPart(new OOXMLPart("ppt/activeX/activeX1.xml", "application/xml", "<ax/>".getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart("ppt/activeX/activeX1.bin", "application/octet-stream", new byte[]{2}));
        pkg.addPart(new OOXMLPart("ppt/ctrlProps/ctrlProp1.xml", "application/xml", "<c/>".getBytes(StandardCharsets.UTF_8)));
        pkg.addContentType("ppt/vbaProject.bin", "application/vnd.ms-office.vbaProject");
        pkg.addContentType("ppt/activeX/activeX1.xml", "application/xml");
        pkg.addContentType("ppt/ctrlProps/ctrlProp1.xml", "application/xml");
        pkg.addRelationship(new OOXMLRelationship("ppt/presentation.xml", "rId1", "vbaProject", "vbaProject.bin", null));
        pkg.addRelationship(new OOXMLRelationship("ppt/presentation.xml", "rId2", "control", "activeX/activeX1.xml", null));
        pkg.addRelationship(new OOXMLRelationship("ppt/presentation.xml", "rId3", "control", "ctrlProps/ctrlProp1.xml", null));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertFalse(pkg.hasPart("ppt/vbaProject.bin"));
        assertFalse(pkg.hasPart("ppt/activeX/activeX1.xml"));
        assertFalse(pkg.hasPart("ppt/activeX/activeX1.bin"));
        assertFalse(pkg.hasPart("ppt/ctrlProps/ctrlProp1.xml"));
        assertTrue(pkg.getRelationships().isEmpty());
        assertNull(pkg.getContentType("ppt/vbaProject.bin"));
        assertNull(pkg.getContentType("ppt/ctrlProps/ctrlProp1.xml"));
    }

    @Test
    void removesActiveSvgAndExternalResourceButPreservesOrdinaryHyperlink() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart(
                "ppt/slides/slide1.xml", "application/xml",
                ("<p:sld xmlns:p=\"p\" xmlns:a=\"a\" xmlns:r=\"r\">" +
                 "<a:blip r:embed=\"rId1\"/><a:hlinkClick r:id=\"rId2\"/>" +
                 "</p:sld>").getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart(
                "ppt/media/image1.svg", "image/svg+xml",
                "<svg><script>alert(1)</script></svg>".getBytes(StandardCharsets.UTF_8)));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                "../media/image1.svg", null));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rId2",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://example.com",
                "External"));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.SUSPICIOUS_SVG));
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXTERNAL_HYPERLINK));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertFalse(pkg.hasPart("ppt/media/image1.svg"));
        assertTrue(pkg.getRelationships().stream().anyMatch(r -> "rId2".equals(r.getId())));
        assertFalse(pkg.getRelationships().stream().anyMatch(r -> "rId1".equals(r.getId())));
    }

    @Test
    void realEmbeddedBatSampleIsDisarmedAndReconstructs() throws Exception {
        Path input = Path.of("samples", "pptx_embedded_bat.pptx");
        assertTrue(Files.exists(input), "Expected real PPTX threat sample: " + input);

        OOXMLPackageReader reader = new OOXMLPackageReader();
        OOXMLPackage pkg = reader.read(input);
        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f ->
                f.getType() == ThreatType.OLE_OBJECT ||
                f.getType() == ThreatType.EXECUTABLE_PAYLOAD));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        Path output = Files.createTempFile("docshield-pptx-threat-", ".pptx");
        try {
            new OOXMLPackageWriter().write(pkg, output);
            OOXMLPackage sanitized = reader.read(output);
            assertFalse(sanitized.hasPart("ppt/embeddings/oleObject1.bin"));
            assertTrue(new OOXMLIntegrityValidator().validate(sanitized));
            assertTrue(new PPTXThreatAnalyzer().analyze(sanitized).stream().noneMatch(f ->
                    f.getType() == ThreatType.OLE_OBJECT ||
                    f.getType() == ThreatType.EXECUTABLE_PAYLOAD));
        } finally {
            Files.deleteIfExists(output);
        }
    }
    @Test
    void removesExternalFileAndPresentationActionsButPreservesNormalHyperlink() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart(
                "ppt/slides/slide1.xml", "application/xml",
                ("<p:sld xmlns:p=\"p\" xmlns:a=\"a\" xmlns:r=\"r\">" +
                 "<a:hlinkClick r:id=\"rIdFile\" action=\"ppaction://hlinkfile\"/>" +
                 "<a:hlinkClick r:id=\"rIdPres\" action=\"ppaction://hlinkpres?slideindex=1\"/>" +
                 "<a:hlinkClick r:id=\"rIdWeb\"/>" +
                 "</p:sld>").getBytes(StandardCharsets.UTF_8)));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rIdFile", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "file:///C:/Windows/System32/calc.exe", "External"));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rIdPres", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://attacker.example/evil.pptx", "External"));
        pkg.addRelationship(new OOXMLRelationship(
                "ppt/slides/slide1.xml", "rIdWeb", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "https://example.com", "External"));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.DANGEROUS_ACTION));
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.DANGEROUS_URI));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);

        assertFalse(pkg.getRelationships().stream().anyMatch(r -> "rIdFile".equals(r.getId())));
        assertFalse(pkg.getRelationships().stream().anyMatch(r -> "rIdPres".equals(r.getId())));
        assertTrue(pkg.getRelationships().stream().anyMatch(r -> "rIdWeb".equals(r.getId())));
        String xml = new String(pkg.getPart("ppt/slides/slide1.xml").getData(), StandardCharsets.UTF_8);
        assertFalse(xml.contains("rIdFile"));
        assertFalse(xml.contains("rIdPres"));
        assertTrue(xml.contains("rIdWeb"));
    }

    @Test
    void genericEmbeddedPackageIsObservedButNotAutomaticallyRemoved() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart(
                "ppt/embeddings/embeddedPackage.bin", "application/octet-stream",
                new byte[]{0x50, 0x4b, 0x03, 0x04, 1, 2, 3}));

        List<SecurityFinding> findings = new PPTXThreatAnalyzer().analyze(pkg);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.EMBEDDED_PACKAGE || f.getType() == ThreatType.OLE_OBJECT));
        assertTrue(findings.stream().noneMatch(f -> f.getType() == ThreatType.EXECUTABLE_PAYLOAD &&
                f.getClassification() != threat.common.FindingClassification.OBSERVATION));

        new OOXMLThreatSanitizer().sanitize(pkg, findings);
        assertTrue(pkg.hasPart("ppt/embeddings/embeddedPackage.bin"));
    }

}

