package threat.pdf;

import identification.Format;
import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.Loader;
import threat.docx.DOCXThreatAnalyzer;
import threat.pptx.PPTXThreatAnalyzer;
import threat.xlsx.XLSXThreatAnalyzer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Inspects the bytes of PDF embedded-file streams before the outer PDF CDR
 * removes the attachment boundary. Supported nested document formats are
 * analyzed with their native analyzer; unsupported payloads are fail-closed.
 * This class does not modify the PDF.
 */
public final class PDFEmbeddedPayloadInspector {
    private static final long MAX_PAYLOAD_BYTES = PDFSecurityPolicy.MAX_EMBEDDED_PAYLOAD_BYTES;
    private static final int MAX_PAYLOADS = PDFSecurityPolicy.MAX_EMBEDDED_PAYLOADS;

    public List<SecurityFinding> inspect(PDDocument document) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (document == null) return findings;
        Set<COSBase> visited = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        int[] count = {0};
        for (PDPage page : document.getPages()) {
            if (page != null) inspectDictionary(page.getCOSObject(), "page", findings, visited, count);
        }
        inspectDictionary(document.getDocumentCatalog().getCOSObject(), "catalog", findings, visited, count);
        return findings;
    }

    private void inspectDictionary(COSDictionary dict, String location,
                                   List<SecurityFinding> findings, Set<COSBase> visited, int[] count) {
        if (dict == null || !visited.add(dict)) return;
        if (count[0] >= MAX_PAYLOADS) {
            findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                    "Embedded payload inspection limit was reached; remaining embedded payloads were not inspected.",
                    "Fail closed and remove/quarantine the PDF."));
            return;
        }
        COSBase type = dict.getDictionaryObject(COSName.TYPE);
        if (type instanceof COSName n && "Filespec".equalsIgnoreCase(n.getName())) {
            COSBase ef = dict.getDictionaryObject(COSName.EF);
            if (ef instanceof COSDictionary efDict) {
                for (var entry : efDict.entrySet()) {
                    COSBase value = entry.getValue();
                    if (value instanceof COSStream stream) {
                        count[0]++;
                        inspectStream(stream, location + "/Filespec/EF/" + entry.getKey().getName(), findings);
                    }
                }
            }
        }
        for (var entry : dict.entrySet()) {
            COSBase value = entry.getValue();
            if (value instanceof COSDictionary child) inspectDictionary(child, location + "/" + entry.getKey().getName(), findings, visited, count);
            else if (value instanceof COSArray array) inspectArray(array, location + "/" + entry.getKey().getName(), findings, visited, count);
        }
    }

    private void inspectArray(COSArray array, String location,
                              List<SecurityFinding> findings, Set<COSBase> visited, int[] count) {
        if (array == null || !visited.add(array)) return;
        for (int i = 0; i < array.size(); i++) {
            if (count[0] >= MAX_PAYLOADS) {
                findings.add(finding(ThreatType.PDF_RESOURCE_LIMIT, ThreatSeverity.CRITICAL, location,
                        "Embedded payload inspection limit was reached; remaining embedded payloads were not inspected.",
                        "Fail closed and remove/quarantine the PDF."));
                return;
            }
            COSBase value = array.getObject(i);
            if (value instanceof COSDictionary child) inspectDictionary(child, location + "[" + i + "]", findings, visited, count);
            else if (value instanceof COSArray nested) inspectArray(nested, location + "[" + i + "]", findings, visited, count);
        }
    }

    private void inspectStream(COSStream stream, String location, List<SecurityFinding> findings) {
        try (InputStream in = stream.createInputStream()) {
            byte[] data = readBounded(in);
            Format format = detect(data);
            if (format == Format.PDF) {
                try (PDDocument nested = Loader.loadPDF(data)) {
                    List<SecurityFinding> nestedFindings = new PDFThreatAnalyzer().analyze(nested);
                    if (hasBlocking(nestedFindings)) {
                        findings.add(finding(ThreatType.PDF_EMBEDDED_FILE, ThreatSeverity.CRITICAL,
                                location, "Embedded PDF contains blocking active content.",
                                "Remove the embedded payload during PDF CDR."));
                    }
                }
                return;
            }
            if (format == Format.DOCX || format == Format.PPTX || format == Format.XLSX) {
                Path temp = Files.createTempFile("docshield-pdf-embedded-", "." + format.name().toLowerCase(Locale.ROOT));
                try {
                    Files.write(temp, data);
                    OOXMLPackage pkg = new OOXMLPackageReader().read(temp);
                    List<SecurityFinding> nested = switch (format) {
                        case DOCX -> new DOCXThreatAnalyzer().analyze(pkg);
                        case PPTX -> new PPTXThreatAnalyzer().analyze(pkg);
                        case XLSX -> new XLSXThreatAnalyzer().analyze(pkg);
                        default -> List.of();
                    };
                    if (hasBlocking(nested)) {
                        findings.add(finding(ThreatType.PDF_EMBEDDED_FILE, ThreatSeverity.CRITICAL,
                                location, "Embedded OOXML document contains blocking active content.",
                                "Remove the embedded payload during PDF CDR."));
                    }
                } finally {
                    Files.deleteIfExists(temp);
                }
                return;
            }
            findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.HIGH, location,
                    "Embedded payload format is not supported for safe recursive inspection.",
                    "Remove the embedded payload during PDF CDR."));
        } catch (Exception ex) {
            findings.add(finding(ThreatType.UNSUPPORTED_CONTENT, ThreatSeverity.CRITICAL, location,
                    "Embedded payload could not be safely inspected: " + safe(ex),
                    "Remove the embedded payload during PDF CDR."));
        }
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        byte[] buffer = new byte[8192];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        long total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > MAX_PAYLOAD_BYTES) throw new IOException("Embedded payload exceeds inspection limit");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static Format detect(byte[] data) throws IOException {
        if (data.length >= 5 && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F' && data[4] == '-') return Format.PDF;
        if (data.length < 4 || data[0] != 'P' || data[1] != 'K') return Format.UNKNOWN;
        boolean docx = false, pptx = false, xlsx = false;
        try (java.util.zip.ZipInputStream zin = new java.util.zip.ZipInputStream(new ByteArrayInputStream(data))) {
            java.util.zip.ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                String n = e.getName().replace('\\', '/');
                if ("word/document.xml".equalsIgnoreCase(n)) docx = true;
                if ("ppt/presentation.xml".equalsIgnoreCase(n)) pptx = true;
                if ("xl/workbook.xml".equalsIgnoreCase(n)) xlsx = true;
                if (docx || pptx || xlsx) break;
            }
        }
        if (docx) return Format.DOCX;
        if (pptx) return Format.PPTX;
        if (xlsx) return Format.XLSX;
        return Format.UNKNOWN;
    }

    private static boolean hasBlocking(List<SecurityFinding> findings) {
        for (SecurityFinding f : findings) if (f != null &&
                (f.getClassification() == FindingClassification.THREAT || f.getClassification() == FindingClassification.POLICY_VIOLATION)) return true;
        return false;
    }

    private static SecurityFinding finding(ThreatType type, ThreatSeverity severity, String location,
                                           String evidence, String action) {
        return new SecurityFinding(FindingClassification.THREAT, type, severity, null,
                location, null, evidence, evidence, action);
    }

    private static String safe(Exception ex) {
        String m = ex.getMessage();
        return m == null ? ex.getClass().getSimpleName() : m.replaceAll("[\\r\\n]+", " ");
    }
}
