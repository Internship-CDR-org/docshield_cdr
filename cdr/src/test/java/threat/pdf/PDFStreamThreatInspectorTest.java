package threat.pdf;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDPage;
import org.junit.jupiter.api.Test;
import sanitization.pdf.PDFThreatSanitizer;

import java.io.OutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** Regression tests for payloads hidden in otherwise ordinary PDF streams. */
class PDFStreamThreatInspectorTest {

    @Test
    void detectsPeSignatureInGenericStream() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSStream stream = document.getDocument().createCOSStream();
            try (OutputStream out = stream.createOutputStream()) {
                byte[] pe = new byte[128];
                pe[0] = 'M'; pe[1] = 'Z';
                pe[0x3c] = 64;
                pe[64] = 'P'; pe[65] = 'E';
                out.write(pe);
            }
            document.getPage(0).getCOSObject().setItem(COSName.CONTENTS, stream);

            var findings = new PDFStreamThreatInspector().inspect(document);
            assertTrue(findings.stream().anyMatch(f -> f.getType() == threat.common.ThreatType.EXECUTABLE_PAYLOAD));
        }
    }

    @Test
    void sanitizerNeutralizesPeStream() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSStream stream = document.getDocument().createCOSStream();
            try (OutputStream out = stream.createOutputStream()) {
                byte[] pe = new byte[128];
                pe[0] = 'M'; pe[1] = 'Z';
                pe[0x3c] = 64;
                pe[64] = 'P'; pe[65] = 'E';
                out.write(pe);
            }
            document.getPage(0).getCOSObject().setItem(COSName.CONTENTS, stream);

            new PDFThreatSanitizer().sanitize(document, new PDFStreamThreatInspector().inspect(document));

            try (var in = stream.createInputStream()) {
                assertEquals(-1, in.read());
            }
        }
    }

    @Test
    void undecodableStreamFailsClosed() throws Exception {
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            COSStream stream = document.getDocument().createCOSStream();
            try (OutputStream out = stream.createOutputStream()) {
                out.write("ordinary-looking bytes".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            }
            // Deliberately use an unknown filter. PDFBox cannot decode this stream,
            // so the security inspector must not silently treat it as safe.
            stream.setItem(COSName.FILTER, COSName.getPDFName("DocShieldUnknownFilter"));
            document.getPage(0).getCOSObject().setItem(COSName.CONTENTS, stream);

            var findings = new PDFStreamThreatInspector().inspect(document);
            assertTrue(findings.stream().anyMatch(f ->
                            f.getType() == threat.common.ThreatType.UNSUPPORTED_CONTENT
                                    && f.getClassification() == threat.common.FindingClassification.THREAT),
                    "An undecodable PDF stream must fail closed instead of becoming a false-safe document.");
        }
    }

    @Test
    void detectsPeInUnreachableXrefStream() throws Exception {
        byte[] pdf = buildPdfWithUnreferencedPeStream();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            var findings = new PDFStreamThreatInspector().inspect(document);
            assertTrue(findings.stream().anyMatch(f -> f.getType() == threat.common.ThreatType.EXECUTABLE_PAYLOAD),
                    "An executable stream present in the PDF xref table must not become a false-safe document merely because it is not linked from the page graph.");
        }
    }

    @Test
    void sanitizerNeutralizesPeInUnreachableXrefStream() throws Exception {
        byte[] pdf = buildPdfWithUnreferencedPeStream();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            var findings = new PDFStreamThreatInspector().inspect(document);
            new PDFThreatSanitizer().sanitize(document, findings);

            boolean executableRemains = new PDFStreamThreatInspector().inspect(document).stream()
                    .anyMatch(f -> f.getType() == threat.common.ThreatType.EXECUTABLE_PAYLOAD);
            assertFalse(executableRemains, "The sanitizer must neutralize executable streams discovered through the xref/object pool.");
        }
    }

    private static byte[] buildPdfWithUnreferencedPeStream() {
        StringBuilder body = new StringBuilder();
        body.append("%PDF-1.7\n");
        int[] offsets = new int[5];

        offsets[1] = body.length();
        body.append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets[2] = body.length();
        body.append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        offsets[3] = body.length();
        body.append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n");

        byte[] payload = new byte[128];
        payload[0] = 'M';
        payload[1] = 'Z';
        payload[0x3c] = 64;
        payload[64] = 'P';
        payload[65] = 'E';
        offsets[4] = body.length();
        body.append("4 0 obj\n<< /Length ").append(payload.length).append(" >>\nstream\n");
        String prefix = body.toString();
        byte[] prefixBytes = prefix.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        String suffix = "\nendstream\nendobj\n";

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            out.write(prefixBytes);
            out.write(payload);
            out.write(suffix.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            int xref = out.size();
            out.write("xref\n0 5\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            out.write("0000000000 65535 f \n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            for (int i = 1; i <= 4; i++) {
                String line = String.format(java.util.Locale.ROOT, "%010d 00000 n \n", offsets[i]);
                out.write(line.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            }
            out.write(("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n")
                    .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            return out.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

}
