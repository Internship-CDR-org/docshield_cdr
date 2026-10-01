package threat.pdf;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSStream;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Byte-level inspection of decoded PDF streams.
 *
 * PDFThreatAnalyzer is intentionally object-graph based. This companion
 * inspector closes the gap where a security-relevant payload is hidden in a
 * stream whose dictionary does not advertise an attachment or active object.
 * It only blocks high-confidence payload signatures; ordinary PDF drawing,
 * image, font and content streams are otherwise left alone.
 */
public final class PDFStreamThreatInspector {
    private static final long MAX_STREAM_BYTES = PDFSecurityPolicy.MAX_EMBEDDED_PAYLOAD_BYTES;
    private static final int MAX_STREAMS = PDFSecurityPolicy.MAX_COS_OBJECTS;

    // Keep the test marker split so source archives do not contain the complete
    // AV-test signature as a contiguous string.
    private static final byte[] EICAR =
            ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" +
             "EICAR-STANDARD-ANTIVIRUS-TEST-" +
             "FILE!$H+H*").getBytes(StandardCharsets.US_ASCII);

    public List<SecurityFinding> inspect(org.apache.pdfbox.pdmodel.PDDocument document) {
        if (document == null || document.getDocumentCatalog() == null) return Collections.emptyList();

        List<SecurityFinding> findings = new ArrayList<>();
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        int[] budget = {0};

        inspectDictionary(document.getDocumentCatalog().getCOSObject(), "catalog", findings, visited, budget);
        int page = 1;
        for (var pdPage : document.getPages()) {
            if (pdPage != null) inspectDictionary(pdPage.getCOSObject(), "page " + page, findings, visited, budget);
            page++;
        }

        // Pass 9: inspect every parsed xref object as well as the normal
        // catalog/page graph. Object streams and unusual indirect references can
        // otherwise leave a decoded stream outside the ordinary traversal path.
        // PDFBox 3.x exposes the parsed xref/object pool through COSDocument.
        inspectXrefObjects(document, findings, visited, budget);
        return findings;
    }

    private void inspectXrefObjects(org.apache.pdfbox.pdmodel.PDDocument document,
                                    List<SecurityFinding> findings, Set<COSBase> visited, int[] budget) {
        try {
            var cosDocument = document.getDocument();
            for (var key : cosDocument.getXrefTable().keySet()) {
                if (budget[0] >= MAX_STREAMS) {
                    findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, "xref",
                            "PDF xref stream inspection object budget was exceeded; remaining objects were not inspected."));
                    return;
                }
                var object = cosDocument.getObjectFromPool(key);
                COSBase value = object == null ? null : resolve(object);
                if (value instanceof COSDictionary dict) {
                    inspectDictionary(dict, "xref " + key, findings, visited, budget);
                }
            }
        } catch (Exception ex) {
            findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.HIGH, "xref",
                    "PDF xref/object-pool inspection could not be completed: " + ex.getClass().getSimpleName()));
        }
    }

    private void inspectDictionary(COSDictionary dict, String location,
                                   List<SecurityFinding> findings, Set<COSBase> visited, int[] budget) {
        if (dict == null || !visited.add(dict)) return;
        if (++budget[0] > MAX_STREAMS) {
            findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                    "PDF stream inspection object budget was exceeded; remaining streams were not inspected."));
            return;
        }

        if (dict instanceof COSStream stream) inspectStream(stream, location, findings);

        for (var entry : dict.entrySet()) {
            COSBase value = resolve(entry.getValue());
            if (value instanceof COSDictionary child) {
                inspectDictionary(child, location + "/" + entry.getKey().getName(), findings, visited, budget);
            } else if (value instanceof org.apache.pdfbox.cos.COSArray array) {
                inspectArray(array, location + "/" + entry.getKey().getName(), findings, visited, budget);
            }
        }
    }

    private void inspectArray(org.apache.pdfbox.cos.COSArray array, String location,
                              List<SecurityFinding> findings, Set<COSBase> visited, int[] budget) {
        if (array == null || !visited.add(array)) return;
        if (++budget[0] > MAX_STREAMS) {
            findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                    "PDF stream inspection object budget was exceeded; remaining streams were not inspected."));
            return;
        }
        for (int i = 0; i < array.size(); i++) {
            COSBase value = resolve(array.get(i));
            if (value instanceof COSDictionary child) {
                inspectDictionary(child, location + "[" + i + "]", findings, visited, budget);
            } else if (value instanceof org.apache.pdfbox.cos.COSArray childArray) {
                inspectArray(childArray, location + "[" + i + "]", findings, visited, budget);
            }
        }
    }

    private static COSBase resolve(COSBase value) {
        while (value instanceof org.apache.pdfbox.cos.COSObject object) {
            value = object.getObject();
        }
        return value;
    }

    private void inspectStream(COSStream stream, String location, List<SecurityFinding> findings) {
        try (InputStream in = stream.createInputStream()) {
            byte[] data = readBounded(in);
            Signature signature = detect(data);
            if (signature != null) {
                findings.add(finding(signature.type, signature.severity, location,
                        signature.evidence));
            }
        } catch (Exception ex) {
            // Pass 10: never convert an undecodable security-relevant stream into
            // a false-safe result. A stream may be compressed with an unsupported
            // filter, malformed, truncated, or otherwise unavailable to the
            // inspection layer. We cannot prove that such bytes are safe, so the
            // document must fail closed. The CDR processor will therefore return
            // a blocking finding and the caller can quarantine the output.
            if (isLimit(ex)) {
                findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                        "PDF stream could not be safely inspected within the configured resource limit."));
            } else {
                findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.CRITICAL, location,
                        "PDF stream could not be decoded or inspected safely ("
                                + ex.getClass().getSimpleName() + ")."));
            }
        }
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > MAX_STREAM_BYTES) throw new IOException("stream exceeds inspection limit");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    public static boolean isExecutableStream(COSStream stream) {
        if (stream == null) return false;
        try (InputStream in = stream.createInputStream()) {
            return detect(readBounded(in)) != null;
        } catch (Exception ex) {
            return false;
        }
    }

    private static Signature detect(byte[] data) {
        if (data.length >= EICAR.length && contains(data, EICAR)) {
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL,
                    "EICAR antivirus-test marker found inside a decoded PDF stream.");
        }
        if (isPe(data)) {
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL,
                    "Structurally valid PE executable signature found in a decoded PDF stream.");
        }
        if (startsWith(data, new byte[]{0x7f,'E','L','F'})) {
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL,
                    "ELF executable signature found at the start of a decoded PDF stream.");
        }
        if (isMachO(data)) {
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL,
                    "Mach-O executable signature found at the start of a decoded PDF stream.");
        }
        if (isScriptShebang(data)) {
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL,
                    "Executable script shebang found at the start of a decoded PDF stream.");
        }
        return null;
    }


    private static boolean isPe(byte[] data) {
        if (data.length < 64 || data[0] != 'M' || data[1] != 'Z') return false;
        int peOffset = (data[0x3c] & 0xff) | ((data[0x3d] & 0xff) << 8)
                | ((data[0x3e] & 0xff) << 16) | ((data[0x3f] & 0xff) << 24);
        if (peOffset < 64 || peOffset > data.length - 4) return false;
        return data[peOffset] == 'P' && data[peOffset + 1] == 'E'
                && data[peOffset + 2] == 0 && data[peOffset + 3] == 0;
    }

    private static boolean isMachO(byte[] d) {
        if (d.length < 4) return false;
        int m = (d[0]&0xff) | ((d[1]&0xff)<<8) | ((d[2]&0xff)<<16) | ((d[3]&0xff)<<24);
        int b = ((d[0]&0xff)<<24) | ((d[1]&0xff)<<16) | ((d[2]&0xff)<<8) | (d[3]&0xff);
        return m == 0xfeedface || m == 0xfeedfacf || m == 0xcefaedfe || m == 0xcffaedfe ||
                b == 0xcafebabe || m == 0xbebafeca;
    }

    private static boolean isScriptShebang(byte[] d) {
        if (d.length < 4 || d[0] != '#' || d[1] != '!') return false;
        String head = new String(d, 0, Math.min(d.length, 256), StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        return head.contains("/sh") || head.contains("/bash") || head.contains("/zsh") ||
                head.contains("/python") || head.contains("/perl") || head.contains("/ruby") ||
                head.contains("/node") || head.contains("wscript") || head.contains("cscript");
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }

    private static boolean contains(byte[] data, byte[] needle) { return indexOf(data, needle, 0) >= 0; }

    private static int indexOf(byte[] data, byte[] needle, int from) {
        outer: for (int i = Math.max(0, from); i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (data[i+j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static boolean isLimit(Exception ex) {
        String m = ex.getMessage();
        return m != null && m.toLowerCase(Locale.ROOT).contains("limit");
    }

    private static SecurityFinding finding(ThreatType type, ThreatSeverity severity, String location, String evidence) {
        return new SecurityFinding(FindingClassification.THREAT, type, severity, null,
                location, null, evidence, evidence,
                type == ThreatType.PDF_RESOURCE_LIMIT ? "Fail closed and quarantine the PDF." :
                        "Remove or neutralize the unsafe PDF stream during CDR.");
    }

    private record Signature(ThreatType type, ThreatSeverity severity, String evidence) {}
}
