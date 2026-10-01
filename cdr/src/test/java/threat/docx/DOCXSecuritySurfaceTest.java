package threat.docx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import sanitization.docx.DOCXThreatSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Word-specific regression checks for active fields, templates, altChunk and external data. */
public final class DOCXSecuritySurfaceTest {
    public static void main(String[] args) {
        OOXMLPackage pkg = new OOXMLPackage();

        pkg.addPart(new OOXMLPart("word/document.xml", "application/xml", (
                "<w:document xmlns:w=\"x\"><w:body><w:p>" +
                "<w:fldChar w:fldCharType=\"begin\"/>" +
                "<w:instrText>INCLU</w:instrText>" +
                "<w:instrText>DEPICTURE file:///secret.jpg</w:instrText>" +
                "<w:fldChar w:fldCharType=\"separate\"/>" +
                "<w:r><w:t>Cached picture result</w:t></w:r>" +
                "<w:fldChar w:fldCharType=\"end\"/>" +
                "</w:p><w:p><w:fldChar w:fldCharType=\"begin\"/>" +
                "<w:instrText>D</w:instrText><w:instrText>DEAUTO excel C:\\\\evil.xls</w:instrText>" +
                "<w:fldChar w:fldCharType=\"separate\"/><w:r><w:t>Cached DDE result</w:t></w:r>" +
                "<w:fldChar w:fldCharType=\"end\"/></w:p></w:body></w:document>")
                .getBytes(StandardCharsets.UTF_8)));

        pkg.addPart(new OOXMLPart("word/settings.xml", "application/xml", (
                "<w:settings xmlns:w=\"x\" xmlns:r=\"r\">" +
                "<w:updateFields w:val=\"true\"/>" +
                "<w:attachedTemplate r:id=\"rTpl\"/>" +
                "<w:mailMerge><w:odso><w:dataSource r:id=\"rSrc\"/></w:odso></w:mailMerge>" +
                "</w:settings>").getBytes(StandardCharsets.UTF_8)));

        pkg.addPart(new OOXMLPart("word/template.dotm",
                "application/vnd.ms-word.template.macroEnabledTemplate.main+xml", new byte[]{1, 2, 3}));

        pkg.addPart(new OOXMLPart("word/altChunk.html", "text/html",
                "<html><script>bad()</script><body>unsafe</body></html>".getBytes(StandardCharsets.UTF_8)));

        pkg.addRelationship(new OOXMLRelationship(
                "word/settings.xml", "rTpl",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
                "template.dotm", "Internal"));
        pkg.addRelationship(new OOXMLRelationship(
                "word/settings.xml", "rSrc",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/mailMergeSource",
                "file:///C:/data.mdb", "External"));
        pkg.addRelationship(new OOXMLRelationship(
                "word/document.xml", "rChunk",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk",
                "altChunk.html", "Internal"));

        DOCXThreatAnalyzer analyzer = new DOCXThreatAnalyzer();
        List<SecurityFinding> findings = analyzer.analyze(pkg);

        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.DDE), "DDE/DDEAUTO not detected");
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXTERNAL_RESOURCE), "External Word field not detected");
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.AUTO_UPDATE_FIELDS), "Automatic field update not detected");
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXTERNAL_TEMPLATE), "Attached template not detected");
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXTERNAL_CONNECTION), "Mail-merge external connection not detected");
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.EMBEDDED_ACTIVE_CONTENT), "Active altChunk not detected");

        new DOCXThreatSanitizer().sanitize(pkg, findings);

        String document = text(pkg, "word/document.xml");
        String settings = text(pkg, "word/settings.xml");

        require(!document.matches("(?is).*<w:instrText[^>]*>.*DDE.*</w:instrText>.*"), "DDE instruction survived sanitization");
        require(!document.contains("DEAUTO"), "DDEAUTO instruction survived sanitization");
        require(!document.contains("INCLUDEPICTURE"), "External field instruction survived sanitization");
        require(document.contains("Cached picture result"), "Cached external-field result was destroyed");
        require(document.contains("Cached DDE result"), "Cached DDE result was destroyed");
        require(!settings.contains("updateFields"), "Automatic field update survived sanitization");
        require(!settings.contains("attachedTemplate"), "Unsafe attached template reference survived sanitization");
        require(!settings.contains("rSrc"), "Mail-merge external relationship reference survived sanitization");
        require(!pkg.hasPart("word/template.dotm"), "Macro-enabled attached template survived sanitization");
        require(!pkg.hasPart("word/altChunk.html"), "Active altChunk survived sanitization");

        System.out.println("DOCX SECURITY SURFACE TEST PASSED");
    }

    private static String text(OOXMLPackage pkg, String partName) {
        return new String(pkg.getPart(partName).getData(), StandardCharsets.UTF_8);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
