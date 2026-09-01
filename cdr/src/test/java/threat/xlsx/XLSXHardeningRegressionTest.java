package threat.xlsx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import sanitization.common.OOXMLThreatSanitizer;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import validation.ooxml.OOXMLIntegrityValidator;
import java.nio.file.Files;
import java.nio.file.Path;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Final XLSX hardening regression checks for detection, preservation and graph cleanup. */
public final class XLSXHardeningRegressionTest {
    public static void main(String[] args) {
        testAllActiveFormulaFunctionsAreRemoved();
        testDefinedNameActiveFormulaIsRemoved();
        testNormalFormulaIsPreserved();
        testNormalHttpsHyperlinkIsPreserved();
        testXlmAndIncomingRelationshipAreRemoved();
        testExternalLinkPartAndRelationshipAreRemoved();
        testConnectionPartAndOutgoingRelationshipsAreRemoved();
        testActiveXRelationshipAndPartAreRemoved();
        testObservedOleIsNotRemoved();
        testDanglingRelationshipIsSanitized();
        testSanitizedWorkbookRoundTripIntegrity();
        System.out.println("XLSX HARDENING REGRESSION TEST PASSED");
    }

    private static void testAllActiveFormulaFunctionsAreRemoved() {
        String[] formulas = {
                "RTD(\"x\",,\"y\")", "CALL(\"x\",\"y\")", "REGISTER.ID(\"x\")",
                "EXEC(\"x\")", "RUN(\"x\")", "GET.CELL(66,A1)", "GET.WORKBOOK(1)",
                "WEBSERVICE(\"https://example\")", "FILTERXML(\"<a/>\",\"//a\")"
        };
        for (String formula : formulas) {
            OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>" + formula + "</f><v>99</v></c>");
            List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
            require(findings.stream().anyMatch(f -> f.getType() == ThreatType.ACTIVE_FORMULA), "active formula not detected: " + formula);
            new OOXMLThreatSanitizer().sanitize(p, findings);
            String xml = text(p.getPart("xl/worksheets/sheet1.xml"));
            require(!xml.contains("<f>"), "active formula survived: " + formula);
            require(xml.contains("<v>99</v>"), "cached value lost: " + formula);
        }
    }

    private static void testDefinedNameActiveFormulaIsRemoved() {
        OOXMLPackage p = workbookPackage("<workbook><definedNames><definedName name=\"evil\">EXEC(\"evil.exe\")</definedName></definedNames></workbook>");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.ACTIVE_FORMULA), "defined-name active formula not detected");
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!text(p.getPart("xl/workbook.xml")).contains("EXEC("), "defined-name active formula survived");
    }

    private static void testNormalFormulaIsPreserved() {
        OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>SUM(1,2)</f><v>3</v></c>");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        require(findings.stream().noneMatch(f -> f.getType() == ThreatType.ACTIVE_FORMULA || f.getType() == ThreatType.EXTERNAL_WORKBOOK), "normal formula falsely classified");
        new OOXMLThreatSanitizer().sanitize(p, findings);
        String xml = text(p.getPart("xl/worksheets/sheet1.xml"));
        require(xml.contains("SUM(1,2)"), "normal formula was removed");
    }

    private static void testNormalHttpsHyperlinkIsPreserved() {
        OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>HYPERLINK(\"https://example.com\",\"open\")</f><v>open</v></c>");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        require(findings.stream().noneMatch(f -> f.getType() == ThreatType.DANGEROUS_URI), "HTTPS hyperlink falsely classified as dangerous");
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(text(p.getPart("xl/worksheets/sheet1.xml")).contains("https://example.com"), "normal HTTPS hyperlink formula was removed");
    }

    private static void testXlmAndIncomingRelationshipAreRemoved() {
        OOXMLPackage p = workbookPackage("<workbook/>");
        OOXMLPart macro = new OOXMLPart("xl/macrosheets/macro1.xml", "application/vnd.ms-excel.macrosheet+xml", "<macro><f>EXEC(\"evil.exe\")</f></macro>".getBytes(StandardCharsets.UTF_8));
        p.addPart(macro);
        p.addRelationship(new OOXMLRelationship("xl/workbook.xml", "rId9", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet", "macrosheets/macro1.xml", null));
        p.addContentType("xl/macrosheets/macro1.xml", "application/vnd.ms-excel.macrosheet+xml");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!p.hasPart("xl/macrosheets/macro1.xml"), "XLM macro part survived");
        require(p.getRelationships().stream().noneMatch(r -> "rId9".equals(r.getId())), "incoming relationship to XLM survived");
        require(p.getContentType("xl/macrosheets/macro1.xml") == null, "XLM content type survived");
    }

    private static void testExternalLinkPartAndRelationshipAreRemoved() {
        OOXMLPackage p = workbookPackage("<workbook/>");
        p.addPart(new OOXMLPart("xl/externalLinks/externalLink1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml", "<externalLink/>".getBytes(StandardCharsets.UTF_8)));
        p.addRelationship(new OOXMLRelationship("xl/workbook.xml", "rId2", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink", "externalLinks/externalLink1.xml", null));
        p.addContentType("xl/externalLinks/externalLink1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!p.hasPart("xl/externalLinks/externalLink1.xml"), "external link part survived");
        require(p.getRelationships().stream().noneMatch(r -> "rId2".equals(r.getId())), "external link relationship survived");
        require(p.getContentType("xl/externalLinks/externalLink1.xml") == null, "external link content type survived");
    }

    private static void testConnectionPartAndOutgoingRelationshipsAreRemoved() {
        OOXMLPackage p = workbookPackage("<workbook/>");
        OOXMLPart conn = new OOXMLPart("xl/connections.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml", "<connections><connection><dbPr connection=\"x\"/></connection></connections>".getBytes(StandardCharsets.UTF_8));
        p.addPart(conn);
        p.addRelationship(new OOXMLRelationship("xl/workbook.xml", "rId3", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/connections", "connections.xml", null));
        p.addRelationship(new OOXMLRelationship("xl/connections.xml", "rId4", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/connection", "https://evil.example/source", "External"));
        p.addContentType("xl/connections.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!p.hasPart("xl/connections.xml"), "connection part survived");
        require(p.getRelationships().stream().noneMatch(r -> "rId3".equals(r.getId()) || "rId4".equals(r.getId())), "connection relationships survived");
    }

    private static void testActiveXRelationshipAndPartAreRemoved() {
        OOXMLPackage p = workbookPackage("<workbook/>");
        p.addPart(new OOXMLPart("xl/activeX/activeX1.bin", "application/vnd.ms-office.activeX", new byte[]{1,2,3}));
        p.addRelationship(new OOXMLRelationship("xl/workbook.xml", "rId5", "http://schemas.microsoft.com/office/2006/relationships/activeX", "activeX/activeX1.bin", null));
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!p.hasPart("xl/activeX/activeX1.bin"), "ActiveX part survived");
        require(p.getRelationships().stream().noneMatch(r -> "rId5".equals(r.getId())), "ActiveX relationship survived");
    }

    private static void testObservedOleIsNotRemoved() {
        OOXMLPackage p = workbookPackage("<workbook/>");
        OOXMLPart ole = new OOXMLPart("xl/embeddings/oleObject1.bin", "application/vnd.ms-office.oleObject", new byte[]{0x01,0x02,0x03});
        p.addPart(ole);
        List<SecurityFinding> findings = List.of(new SecurityFinding(FindingClassification.OBSERVATION, ThreatType.OLE_OBJECT, threat.common.ThreatSeverity.INFO, ole, null, null, "OLE object observed", "", "preserve"));
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(p.hasPart("xl/embeddings/oleObject1.bin"), "observed OLE object was incorrectly removed");
    }

    private static void testDanglingRelationshipIsSanitized() {
        OOXMLPackage p = workbookPackage("<workbook><externalLinks><externalLink r:id=\"rBad\"/></externalLinks></workbook>");
        List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
        require(findings.stream().anyMatch(f -> f.getType() == ThreatType.INVALID_RELATIONSHIP), "dangling relationship not detected");
        new OOXMLThreatSanitizer().sanitize(p, findings);
        require(!text(p.getPart("xl/workbook.xml")).contains("rBad"), "dangling relationship reference survived");
    }

    private static void testSanitizedWorkbookRoundTripIntegrity() {
        try {
            OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>RTD(\"x\",,\"y\")</f><v>123</v></c><c r=\"A2\"><f>SUM(1,2)</f><v>3</v></c>");
            List<SecurityFinding> findings = new XLSXThreatAnalyzer().analyze(p);
            new OOXMLThreatSanitizer().sanitize(p, findings);
            Path out = Files.createTempFile("docshield-xlsx-hardening-", ".xlsx");
            new OOXMLPackageWriter().write(p, out);
            OOXMLPackage q = new OOXMLPackageReader().read(out);
            require(new OOXMLIntegrityValidator().validate(q), "sanitized XLSX failed structural validation");
            String xml = text(q.getPart("xl/worksheets/sheet1.xml"));
            require(!xml.contains("RTD("), "RTD survived round trip");
            require(xml.contains("<v>123</v>"), "RTD cached value lost after round trip");
            require(xml.contains("SUM(1,2)"), "benign formula lost after round trip");
            Files.deleteIfExists(out);
        } catch (Exception e) {
            throw new AssertionError("round-trip integrity test failed", e);
        }
    }

    private static OOXMLPackage sheetPackage(String cell) {
        OOXMLPackage p = workbookPackage("<workbook/>");
        p.addPart(new OOXMLPart("xl/worksheets/sheet1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml", ("<worksheet><sheetData>" + cell + "</sheetData></worksheet>").getBytes(StandardCharsets.UTF_8)));
        p.addContentType("xl/worksheets/sheet1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml");
        return p;
    }

    private static OOXMLPackage workbookPackage(String workbookXml) {
        OOXMLPackage p = new OOXMLPackage();
        p.addPart(new OOXMLPart("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", workbookXml.getBytes(StandardCharsets.UTF_8)));
        p.addPart(new OOXMLPart("[Content_Types].xml", "application/xml", "<Types/>".getBytes(StandardCharsets.UTF_8)));
        p.addContentType("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml");
        p.addContentType("[Content_Types].xml", "application/xml");
        return p;
    }

    private static String text(OOXMLPart p) { return new String(p.getData(), StandardCharsets.UTF_8); }
    private static void require(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }
}
