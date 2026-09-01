package threat.pdf;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * PDF object-graph security analyzer.  It deliberately does not rely on
 * textual signatures: security-relevant dictionaries are followed through
 * indirect objects, arrays, page annotations, form fields, name trees and
 * action chains.
 */
public final class PDFThreatAnalyzer {
    private static final Set<String> BLOCKING_ACTIONS = Set.of(
            "JAVASCRIPT", "LAUNCH", "GOTOR", "GOTOE", "SUBMITFORM",
            "IMPORTDATA", "RENDITION", "MOVIE", "SOUND", "RICHMEDIAEXECUTE"
    );

    private static final Set<String> ACTIVE_SUBTYPES = Set.of(
            "FILEATTACHMENT", "RICHMEDIA", "3D", "MOVIE", "SOUND", "SCREEN"
    );

    private static final Set<String> ACTIVE_RESOURCE_KEYS = Set.of(
            "RICHMEDIA", "RICHMEDIACONTENT", "RICHMEDIASETTINGS", "3D", "3DA"
    );

    private static final int MAX_OBJECTS = PDFSecurityPolicy.MAX_COS_OBJECTS;

    public List<SecurityFinding> analyze(Path file) throws IOException {
        try (PDDocument document = Loader.loadPDF(file.toFile())) {
            return analyze(document);
        }
    }

    public List<SecurityFinding> analyze(PDDocument document) {
        if (document == null || document.getDocumentCatalog() == null) return Collections.emptyList();

        List<SecurityFinding> findings = new ArrayList<>();
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        int[] budget = {0};
        boolean[] limitReported = {false};
        COSDictionary catalog = document.getDocumentCatalog().getCOSObject();

        if (document.isEncrypted()) {
            add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.PDF_ENCRYPTION,
                    ThreatSeverity.MEDIUM, "PDF", null,
                    "The PDF is encrypted; CDR will create a fresh output after successful decryption.",
                    "Reconstruct without source encryption.");
        }

        scanDictionary(catalog, "catalog", findings, visited, budget, limitReported, 0);

        int pageNumber = 1;
        for (PDPage page : document.getPages()) {
            if (page != null) {
                scanDictionary(page.getCOSObject(), "page " + pageNumber, findings, visited, budget, limitReported, 0);
            }
            pageNumber++;
        }

        return deduplicate(findings);
    }

    private void scanDictionary(COSDictionary dict, String location,
                                List<SecurityFinding> findings, Set<COSBase> visited, int[] budget,
                                boolean[] limitReported, int depth) {
        if (dict == null || !visited.add(dict)) return;
        if (depth > PDFSecurityPolicy.MAX_COS_GRAPH_DEPTH) {
            reportTraversalLimit(findings, limitReported, location);
            return;
        }
        if (++budget[0] > MAX_OBJECTS) {
            reportTraversalLimit(findings, limitReported, location);
            return;
        }

        COSBase actionType = dict.getDictionaryObject(COSName.S);
        if (actionType instanceof COSName actionName) {
            String type = actionName.getName().toUpperCase(Locale.ROOT);
            if ("JAVASCRIPT".equals(type)) {
                add(findings, FindingClassification.THREAT, ThreatType.PDF_JAVASCRIPT,
                        ThreatSeverity.CRITICAL, location, null,
                        "PDF JavaScript action detected at " + location + ".",
                        "Remove the JavaScript action and its action chain.");
            } else if (BLOCKING_ACTIONS.contains(type)) {
                add(findings, FindingClassification.THREAT, ThreatType.PDF_ACTIVE_ACTION,
                        ThreatSeverity.CRITICAL, location, null,
                        "Active PDF action /" + type + " detected at " + location + ".",
                        "Remove the active action and its chained actions.");
            } else if ("URI".equals(type)) {
                String uri = stringValue(dict.getDictionaryObject(COSName.URI));
                if (isDangerousUri(uri)) {
                    add(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_URI,
                            ThreatSeverity.CRITICAL, location, null,
                            "Dangerous URI scheme detected: " + uri,
                            "Remove the URI action.");
                } else if (uri != null && !uri.isBlank()) {
                    add(findings, FindingClassification.OBSERVATION, ThreatType.EXTERNAL_HYPERLINK,
                            ThreatSeverity.INFO, location, null,
                            "External PDF URI preserved: " + uri,
                            "Preserve approved ordinary web/mail hyperlinks.");
                }
            }
        }

        if (dict.getDictionaryObject(COSName.JS) != null ||
                dict.getDictionaryObject(COSName.getPDFName("JavaScript")) != null) {
            add(findings, FindingClassification.THREAT, ThreatType.PDF_JAVASCRIPT,
                    ThreatSeverity.CRITICAL, location, null,
                    "Direct PDF JavaScript entry detected at " + location + ".",
                    "Remove the JavaScript entry.");
        }

        for (String key : ACTIVE_RESOURCE_KEYS) {
            if (dict.getDictionaryObject(COSName.getPDFName(key)) != null) {
                add(findings, FindingClassification.THREAT, ThreatType.PDF_RICH_MEDIA,
                        ThreatSeverity.HIGH, location, null,
                        "Active PDF multimedia/3D content /" + key + " detected at " + location + ".",
                        "Remove the active multimedia/3D resource.");
            }
        }

        COSBase subtype = dict.getDictionaryObject(COSName.SUBTYPE);
        if (subtype instanceof COSName subtypeName) {
            String name = subtypeName.getName().toUpperCase(Locale.ROOT);
            if (ACTIVE_SUBTYPES.contains(name)) {
                ThreatType type = "FILEATTACHMENT".equals(name)
                        ? ThreatType.PDF_EMBEDDED_FILE : ThreatType.PDF_RICH_MEDIA;
                add(findings, FindingClassification.THREAT, type,
                        ThreatSeverity.HIGH, location, null,
                        "Active PDF annotation subtype /" + name + " detected at " + location + ".",
                        "Remove the active annotation and any associated payload.");
            }
        }

        COSBase fileSpecType = dict.getDictionaryObject(COSName.TYPE);
        if (fileSpecType instanceof COSName fileSpecName &&
                "Filespec".equalsIgnoreCase(fileSpecName.getName())) {
            if (dict.getDictionaryObject(COSName.EF) != null || dict.getDictionaryObject(COSName.F) != null ||
                    dict.getDictionaryObject(COSName.UF) != null || dict.getDictionaryObject(COSName.getPDFName("AF")) != null) {
                add(findings, FindingClassification.THREAT, ThreatType.PDF_EMBEDDED_FILE,
                        ThreatSeverity.HIGH, location, null,
                        "PDF file specification or embedded-file reference detected at " + location + ".",
                        "Remove the file specification and embedded payload reference.");
            }
        }

        if (dict.getDictionaryObject(COSName.EF) != null ||
                dict.getDictionaryObject(COSName.getPDFName("EmbeddedFiles")) != null ||
                isEmbeddedFileStream(dict)) {
            add(findings, FindingClassification.THREAT, ThreatType.PDF_EMBEDDED_FILE,
                    ThreatSeverity.HIGH, location, null,
                    "Embedded file payload detected at " + location + ".",
                    "Remove embedded file payloads and attachment references.");
        }

        if (dict.getDictionaryObject(COSName.getPDFName("XFA")) != null) {
            add(findings, FindingClassification.THREAT, ThreatType.PDF_XFA,
                    ThreatSeverity.HIGH, location, null,
                    "XFA form content detected at " + location + ".",
                    "Remove XFA while retaining ordinary AcroForm fields where possible.");
        }

        COSBase ft = dict.getDictionaryObject(COSName.getPDFName("FT"));
        COSBase type = dict.getDictionaryObject(COSName.TYPE);
        if ((ft instanceof COSName ftName && "Sig".equalsIgnoreCase(ftName.getName())) ||
                (type instanceof COSName typeName && "Sig".equalsIgnoreCase(typeName.getName()))) {
            add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.PDF_SIGNATURE,
                    ThreatSeverity.MEDIUM, location, null,
                    "A digital signature is present. A new CDR PDF cannot retain the original byte-range signature.",
                    "Remove signature material and create a new unsigned PDF.");
        }

        for (var entry : dict.entrySet()) {
            COSBase value = resolve(entry.getValue());

            if (value instanceof COSDictionary child) {
                scanDictionary(
                        child,
                        location + "/" + entry.getKey().getName(),
                        findings,
                        visited,
                        budget,
                        limitReported,
                        depth + 1
                );
            } else if (value instanceof COSArray array) {
                scanArray(
                        array,
                        location + "/" + entry.getKey().getName(),
                        findings,
                        visited,
                        budget,
                        limitReported,
                        depth + 1
                );
            }
        }
    }

    private void scanArray(COSArray array, String location,
                           List<SecurityFinding> findings, Set<COSBase> visited, int[] budget,
                           boolean[] limitReported, int depth) {
        if (array == null || !visited.add(array)) return;
        if (depth > PDFSecurityPolicy.MAX_COS_GRAPH_DEPTH) {
            reportTraversalLimit(findings, limitReported, location);
            return;
        }
        if (++budget[0] > MAX_OBJECTS) {
            reportTraversalLimit(findings, limitReported, location);
            return;
        }
        for (int i = 0; i < array.size(); i++) {
            COSBase value = resolve(array.get(i));

            if (value instanceof COSDictionary child) {
                scanDictionary(
                        child,
                        location + "[" + i + "]",
                        findings,
                        visited,
                        budget,
                        limitReported,
                        depth + 1
                );
            } else if (value instanceof COSArray childArray) {
                scanArray(
                        childArray,
                        location + "[" + i + "]",
                        findings,
                        visited,
                        budget,
                        limitReported,
                        depth + 1
                );
            }
        }
    }

    private static COSBase resolve(COSBase value) {
        while (value instanceof COSObject object) {
            value = object.getObject();
        }
        return value;
    }

    private static boolean isEmbeddedFileStream(COSDictionary dict) {
        COSBase type = dict.getDictionaryObject(COSName.TYPE);
        return type instanceof COSName n && "EmbeddedFile".equalsIgnoreCase(n.getName());
    }

    private static String stringValue(COSBase base) {
        if (base instanceof COSString s) return s.getString();
        return base == null ? null : base.toString();
    }

    static boolean isDangerousUri(String uri) {
        return PDFSecurityPolicy.isDangerousUri(uri);
    }

    private static void reportTraversalLimit(List<SecurityFinding> findings, boolean[] limitReported, String location) {
        if (limitReported[0]) return;
        limitReported[0] = true;
        add(findings, FindingClassification.THREAT, ThreatType.PDF_RESOURCE_LIMIT,
                ThreatSeverity.CRITICAL, location, null,
                "PDF object-graph inspection exceeded the configured safety limit; inspection is incomplete.",
                "Do not release the document as safe; fail closed and quarantine it.");
    }

    private static void add(List<SecurityFinding> findings, FindingClassification classification,
                            ThreatType type, ThreatSeverity severity, String location,
                            String relationshipId, String evidence, String action) {
        findings.add(new SecurityFinding(classification, type, severity, null,
                location, relationshipId, evidence, evidence, action));
    }

    private static List<SecurityFinding> deduplicate(List<SecurityFinding> input) {
        List<SecurityFinding> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (SecurityFinding f : input) {
            String key = f.getType() + "|" + f.getClassification() + "|" + f.getEvidence();
            if (seen.add(key)) result.add(f);
        }
        return result;
    }
}
