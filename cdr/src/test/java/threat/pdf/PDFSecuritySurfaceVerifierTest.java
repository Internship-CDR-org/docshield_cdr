package threat.pdf;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PDFSecuritySurfaceVerifierTest {
    @Test
    void independentlyDetectsSurvivingJavaScriptSurface() throws Exception {
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage());
            doc.getDocumentCatalog().getCOSObject().setItem(COSName.JS, COSName.getPDFName("survived"));
            List<SecurityFinding> findings = new PDFSecuritySurfaceVerifier().verify(doc);
            assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.PDF_JAVASCRIPT));
        }
    }

    @Test
    void independentlyDetectsExecutableStream() throws Exception {
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage());
            COSStream stream = doc.getDocument().createCOSStream();
            try (var out = stream.createOutputStream()) {
                byte[] pe = new byte[128];
                pe[0] = 'M'; pe[1] = 'Z';
                int off = 64;
                pe[0x3c] = (byte) off;
                pe[off] = 'P'; pe[off + 1] = 'E';
                doc.getDocumentCatalog().getCOSObject().setItem(COSName.CONTENTS, stream);
                out.write(pe);
            }
            List<SecurityFinding> findings = new PDFSecuritySurfaceVerifier().verify(doc);
            assertTrue(findings.stream().anyMatch(f -> f.getType() == ThreatType.EXECUTABLE_PAYLOAD));
        }
    }
}
