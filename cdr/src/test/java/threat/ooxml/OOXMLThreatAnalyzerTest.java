package threat.ooxml;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import org.junit.jupiter.api.Test;
import threat.common.ThreatType;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class OOXMLThreatAnalyzerTest {
    @Test
    void detectsCommonThreatCapabilities() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("xl/vbaProject.bin", "application/vnd.ms-office.vbaProject", new byte[]{1}));
        pkg.addPart(new OOXMLPart("xl/embeddings/evil.exe", "application/octet-stream", new byte[]{'M','Z'}));
        pkg.addPart(new OOXMLPart("xl/macrosheets/sheet1.xml", "application/xml", "<m/>".getBytes()));
        pkg.addPart(new OOXMLPart("xl/worksheets/sheet1.xml", "application/xml",
                "<worksheet><f>cmd|' /c calc'!A1</f></worksheet>".getBytes()));
        pkg.addRelationship(new OOXMLRelationship("xl/worksheets/sheet1.xml", "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                "javascript:alert(1)", "External"));

        Set<ThreatType> types = new OOXMLThreatAnalyzer().analyze(pkg).stream()
                .map(f -> f.getType()).collect(Collectors.toSet());

        assertTrue(types.contains(ThreatType.VBA_PROJECT));
        assertTrue(types.contains(ThreatType.EXECUTABLE_PAYLOAD));
        assertTrue(types.contains(ThreatType.XLM_MACRO));
        assertTrue(types.contains(ThreatType.DDE));
        assertTrue(types.contains(ThreatType.DANGEROUS_URI));
    }
}
