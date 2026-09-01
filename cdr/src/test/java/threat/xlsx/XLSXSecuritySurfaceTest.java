package threat.xlsx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import sanitization.common.OOXMLThreatSanitizer;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Lightweight security-surface regression checks for Excel-specific findings. */
public final class XLSXSecuritySurfaceTest {
    public static void main(String[] args) {
        testExternalFormula();
        testActiveFormula();
        testDangerousHyperlink();
        testXlm();
        testConnection();
        System.out.println("XLSX SECURITY SURFACE TEST PASSED");
    }

    private static void testExternalFormula() {
        OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>[evil.xlsx]Sheet1!A1</f><v>42</v></c>");
        List<SecurityFinding> f = new XLSXThreatAnalyzer().analyze(p);
        require(f.stream().anyMatch(x -> x.getType() == ThreatType.EXTERNAL_WORKBOOK), "external workbook formula not detected");
        new OOXMLThreatSanitizer().sanitize(p, f);
        String xml = text(p.getPart("xl/worksheets/sheet1.xml"));
        require(!xml.contains("[evil.xlsx]"), "external formula survived");
        require(xml.contains("<v>42</v>"), "cached value was not preserved");
    }

    private static void testActiveFormula() {
        OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>RTD(\"evil\",,\"x\")</f><v>7</v></c>");
        List<SecurityFinding> f = new XLSXThreatAnalyzer().analyze(p);
        require(f.stream().anyMatch(x -> x.getType() == ThreatType.ACTIVE_FORMULA), "RTD not detected");
        new OOXMLThreatSanitizer().sanitize(p, f);
        String xml = text(p.getPart("xl/worksheets/sheet1.xml"));
        require(!xml.contains("RTD("), "RTD formula survived");
        require(xml.contains("<v>7</v>"), "cached value was not preserved");
    }

    private static void testDangerousHyperlink() {
        OOXMLPackage p = sheetPackage("<c r=\"A1\"><f>HYPERLINK(\"file:///C:/evil.exe\",\"open\")</f><v>open</v></c>");
        List<SecurityFinding> f = new XLSXThreatAnalyzer().analyze(p);
        require(f.stream().anyMatch(x -> x.getType() == ThreatType.DANGEROUS_URI), "dangerous hyperlink not detected");
        new OOXMLThreatSanitizer().sanitize(p, f);
        require(!text(p.getPart("xl/worksheets/sheet1.xml")).contains("file:///C:/evil.exe"), "dangerous hyperlink survived");
    }

    private static void testXlm() {
        OOXMLPackage p = sheetPackage("");
        OOXMLPart macro = new OOXMLPart("xl/macrosheets/macro1.xml", "application/vnd.ms-excel.macrosheet+xml", "<f>EXEC(\"evil.exe\")</f>".getBytes(StandardCharsets.UTF_8));
        p.addPart(macro);
        List<SecurityFinding> f = new XLSXThreatAnalyzer().analyze(p);
        require(f.stream().anyMatch(x -> x.getType() == ThreatType.XLM_MACRO), "XLM macro not detected");
        new OOXMLThreatSanitizer().sanitize(p, f);
        require(!p.hasPart("xl/macrosheets/macro1.xml"), "XLM macro survived");
    }

    private static void testConnection() {
        OOXMLPackage p = sheetPackage("");
        OOXMLPart conn = new OOXMLPart("xl/connections.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml", "<connections><connection><webPr url=\"https://evil.example\"/></connection></connections>".getBytes(StandardCharsets.UTF_8));
        p.addPart(conn);
        List<SecurityFinding> f = new XLSXThreatAnalyzer().analyze(p);
        require(f.stream().anyMatch(x -> x.getType() == ThreatType.EXTERNAL_CONNECTION), "connection not detected");
        new OOXMLThreatSanitizer().sanitize(p, f);
        require(!p.hasPart("xl/connections.xml"), "connection part survived");
    }

    private static OOXMLPackage sheetPackage(String cellXml) {
        OOXMLPackage p = new OOXMLPackage();
        p.addPart(new OOXMLPart("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", "<workbook/>".getBytes(StandardCharsets.UTF_8)));
        p.addPart(new OOXMLPart("xl/worksheets/sheet1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml", ("<worksheet><sheetData>" + cellXml + "</sheetData></worksheet>").getBytes(StandardCharsets.UTF_8)));
        return p;
    }

    private static String text(OOXMLPart p) { return new String(p.getData(), StandardCharsets.UTF_8); }
    private static void require(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }
}
