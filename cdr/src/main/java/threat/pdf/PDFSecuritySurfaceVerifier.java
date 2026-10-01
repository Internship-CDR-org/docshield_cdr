package threat.pdf;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * Independent post-CDR security-surface verifier.
 *
 * This deliberately does not call PDFThreatAnalyzer or PDFStreamThreatInspector.
 * Its purpose is to provide a second implementation of the most important
 * invariants that must hold after reconstruction: no executable payload
 * signatures and no known active-content dictionary surfaces.
 */
public final class PDFSecuritySurfaceVerifier {
    private static final long MAX_BYTES = PDFSecurityPolicy.MAX_EMBEDDED_PAYLOAD_BYTES;
    private static final int MAX_OBJECTS = PDFSecurityPolicy.MAX_COS_OBJECTS;

    private static final Set<String> ACTIVE_KEYS = Set.of(
            "JavaScript", "JS", "AA", "OpenAction", "RichMedia", "RichMediaContent",
            "RichMediaSettings", "3D", "3DA", "XFA", "AF", "EmbeddedFiles"
    );

    public List<SecurityFinding> verify(PDDocument document) {
        if (document == null || document.getDocumentCatalog() == null) return Collections.emptyList();
        List<SecurityFinding> findings = new ArrayList<>();
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        int[] budget = {0};
        verifyValue(document.getDocumentCatalog().getCOSObject(), "catalog", findings, visited, budget);
        for (int i = 0; i < document.getPages().getCount(); i++) {
            verifyValue(document.getPage(i).getCOSObject(), "page " + (i + 1), findings, visited, budget);
        }
        verifyXrefObjects(document, findings, visited, budget);
        return findings;
    }

    private void verifyXrefObjects(PDDocument document, List<SecurityFinding> findings,
                                   Set<COSBase> visited, int[] budget) {
        try {
            for (var key : document.getDocument().getXrefTable().keySet()) {
                if (budget[0] >= MAX_OBJECTS) {
                    findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL,
                            "xref", "Independent PDF security verification exceeded its object budget."));
                    return;
                }
                COSObject object = document.getDocument().getObjectFromPool(key);
                if (object != null) verifyValue(object.getObject(), "xref " + key, findings, visited, budget);
            }
        } catch (Exception ex) {
            findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.CRITICAL,
                    "xref", "Independent PDF security verification could not inspect the xref object pool."));
        }
    }

    private void verifyValue(COSBase raw, String location, List<SecurityFinding> findings,
                             Set<COSBase> visited, int[] budget) {
        COSBase value = dereference(raw);
        if (value == null || !visited.add(value)) return;
        if (++budget[0] > MAX_OBJECTS) {
            findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                    "Independent PDF security verification exceeded its object budget."));
            return;
        }
        if (value instanceof COSStream stream) {
            verifyStream(stream, location, findings);
        }
        if (value instanceof COSDictionary dict) {
            for (var entry : dict.entrySet()) {
                String key = entry.getKey().getName();
                if (ACTIVE_KEYS.contains(key)) {
                    findings.add(finding(activeType(key), ThreatSeverity.CRITICAL, location + "/" + key,
                            "Prohibited active-content dictionary entry survived reconstruction: /" + key));
                }
                verifyValue(entry.getValue(), location + "/" + key, findings, visited, budget);
            }
        } else if (value instanceof COSArray array) {
            for (int i = 0; i < array.size(); i++) {
                verifyValue(array.get(i), location + "[" + i + "]", findings, visited, budget);
            }
        }
    }

    private void verifyStream(COSStream stream, String location, List<SecurityFinding> findings) {
        try (InputStream in = stream.createInputStream()) {
            byte[] data = readBounded(in);
            if (isPe(data) || startsWith(data, new byte[]{0x7f, 'E', 'L', 'F'}) || isMachO(data)) {
                findings.add(finding(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL, location,
                        "Executable binary signature survived reconstruction in a PDF stream."));
            }
        } catch (Exception ex) {
            findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.CRITICAL, location,
                    "Independent verifier could not decode a reconstructed PDF stream."));
        }
    }

    private static COSBase dereference(COSBase value) {
        while (value instanceof COSObject object) value = object.getObject();
        return value;
    }

    private static byte[] readBounded(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            total += n;
            if (total > MAX_BYTES) throw new IllegalStateException("stream limit");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private static boolean isPe(byte[] d) {
        if (d.length < 64 || d[0] != 'M' || d[1] != 'Z') return false;
        int p = (d[0x3c] & 255) | ((d[0x3d] & 255) << 8) | ((d[0x3e] & 255) << 16) | ((d[0x3f] & 255) << 24);
        return p >= 64 && p <= d.length - 4 && d[p] == 'P' && d[p + 1] == 'E' && d[p + 2] == 0 && d[p + 3] == 0;
    }

    private static boolean isMachO(byte[] d) {
        if (d.length < 4) return false;
        int m = (d[0]&255) | ((d[1]&255)<<8) | ((d[2]&255)<<16) | ((d[3]&255)<<24);
        int b = ((d[0]&255)<<24) | ((d[1]&255)<<16) | ((d[2]&255)<<8) | (d[3]&255);
        return m == 0xfeedface || m == 0xfeedfacf || m == 0xcefaedfe || m == 0xcffaedfe || b == 0xcafebabe || m == 0xbebafeca;
    }

    private static boolean startsWith(byte[] d, byte[] p) {
        if (d.length < p.length) return false;
        for (int i = 0; i < p.length; i++) if (d[i] != p[i]) return false;
        return true;
    }

    private static ThreatType activeType(String key) {
        if ("JavaScript".equals(key) || "JS".equals(key)) return ThreatType.PDF_JAVASCRIPT;
        if ("XFA".equals(key)) return ThreatType.PDF_XFA;
        if ("EmbeddedFiles".equals(key) || "AF".equals(key)) return ThreatType.PDF_EMBEDDED_FILE;
        if ("RichMedia".equals(key) || "RichMediaContent".equals(key) || "RichMediaSettings".equals(key)) return ThreatType.PDF_RICH_MEDIA;
        return ThreatType.PDF_ACTIVE_ACTION;
    }

    private static SecurityFinding finding(ThreatType type, ThreatSeverity severity, String location, String evidence) {
        return new SecurityFinding(FindingClassification.THREAT, type, severity, null, location, null,
                evidence, evidence, "Quarantine the reconstructed PDF; the required security invariant did not hold.");
    }
}
