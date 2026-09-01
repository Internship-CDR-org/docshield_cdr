package sanitization.common;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import threat.docx.DOCXThreatAnalyzer;
import threat.ooxml.OOXMLThreatAnalyzer;
import threat.pptx.PPTXThreatAnalyzer;
import threat.xlsx.XLSXThreatAnalyzer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Performs recursive CDR on OOXML packages embedded inside OOXML packages.
 *
 * The outer package is not treated as an opaque binary boundary when the
 * embedded payload is itself an OOXML package. A nested package is parsed,
 * analyzed and sanitized with the same security model, reconstructed in
 * memory, and written back into the containing part when it is clean after
 * sanitization. If the nested package cannot be safely inspected or remains
 * unsafe after sanitization, the containing embedded package is removed.
 *
 * Resource limits are safety controls, not format capabilities. Reaching a
 * limit produces an explicit blocking finding; content is never silently
 * trusted merely because recursive inspection stopped.
 */
public final class RecursiveOOXMLSanitizer {

    public static final int DEFAULT_MAX_DEPTH = 4;
    public static final long DEFAULT_MAX_EMBEDDED_BYTES = 64L * 1024L * 1024L;
    public static final int DEFAULT_MAX_ZIP_ENTRIES = 10_000;
    public static final int DEFAULT_MAX_EMBEDDED_PACKAGES = 256;

    private final int maxDepth;
    private final long maxEmbeddedBytes;
    private final int maxZipEntries;
    private final int maxEmbeddedPackages;

    private final OOXMLPackageReader reader = new OOXMLPackageReader();
    private final OOXMLPackageWriter writer = new OOXMLPackageWriter();
    private final OOXMLThreatAnalyzer commonAnalyzer = new OOXMLThreatAnalyzer();
    private final OOXMLThreatSanitizer sanitizer = new OOXMLThreatSanitizer();

    public RecursiveOOXMLSanitizer() {
        this(DEFAULT_MAX_DEPTH, DEFAULT_MAX_EMBEDDED_BYTES,
                DEFAULT_MAX_ZIP_ENTRIES, DEFAULT_MAX_EMBEDDED_PACKAGES);
    }

    public RecursiveOOXMLSanitizer(int maxDepth,
                                   long maxEmbeddedBytes,
                                   int maxZipEntries,
                                   int maxEmbeddedPackages) {
        if (maxDepth < 0) throw new IllegalArgumentException("maxDepth must be >= 0");
        if (maxEmbeddedBytes <= 0) throw new IllegalArgumentException("maxEmbeddedBytes must be > 0");
        if (maxZipEntries <= 0) throw new IllegalArgumentException("maxZipEntries must be > 0");
        if (maxEmbeddedPackages <= 0) throw new IllegalArgumentException("maxEmbeddedPackages must be > 0");
        this.maxDepth = maxDepth;
        this.maxEmbeddedBytes = maxEmbeddedBytes;
        this.maxZipEntries = maxZipEntries;
        this.maxEmbeddedPackages = maxEmbeddedPackages;
    }

    /**
     * Sanitizes embedded OOXML packages in-place.
     *
     * Findings from nested packages are appended to the supplied list. The
     * returned actions include both nested and outer-package changes.
     */
    public Result sanitizeEmbeddedPackages(OOXMLPackage outer,
                                           List<SecurityFinding> findings) {
        List<String> actions = new ArrayList<>();
        if (outer == null) return new Result(actions, 0, false);

        Context context = new Context(findings, actions);
        sanitizePackageEmbeddings(outer, 0, "root", context);
        return new Result(actions, context.packagesInspected, context.limitReached);
    }


    /**
     * Verifies embedded OOXML content without mutating the package. This is
     * used after reconstruction so the CDR result cannot report success while
     * a blocking threat remains hidden in an embedded document.
     */
    public boolean hasBlockingEmbeddedContent(OOXMLPackage outer) {
        if (outer == null) return true;
        return hasBlockingEmbeddedContent(outer, 0, new Counter());
    }

    private boolean hasBlockingEmbeddedContent(OOXMLPackage pkg, int depth, Counter counter) {
        for (OOXMLPart part : new ArrayList<>(pkg.getParts())) {
            if (part == null || part.getPartName() == null || part.getData() == null || !isEmbeddedCandidate(part)) continue;
            byte[] data = part.getData();
            if (depth >= maxDepth || data.length > maxEmbeddedBytes || counter.packages >= maxEmbeddedPackages) return true;
            if (!looksLikeOOXMLZip(data)) {
                if (looksLikeOle(data) && containsUnsafeOOXMLInsideOle(data, depth + 1, part.getPartName(), new Context(null, new ArrayList<>()))) return true;
                continue;
            }
            try {
                counter.packages++;
                OOXMLPackage nested = reader.read(new ByteArrayInputStream(data));
                if (hasBlockingFinding(analyze(nested))) return true;
                if (hasBlockingEmbeddedContent(nested, depth + 1, counter)) return true;
            } catch (Exception ex) {
                return true;
            }
        }
        return false;
    }

    private void sanitizePackageEmbeddings(OOXMLPackage pkg,
                                           int depth,
                                           String location,
                                           Context context) {
        if (pkg == null) return;

        List<OOXMLPart> snapshot = new ArrayList<>(pkg.getParts());
        for (OOXMLPart part : snapshot) {
            if (part == null || part.getPartName() == null || part.getData() == null) continue;
            if (!isEmbeddedCandidate(part)) continue;
            sanitizeEmbeddedPart(pkg, part, depth, location + "!" + part.getPartName(), context);
        }
    }

    private void sanitizeEmbeddedPart(OOXMLPackage outer,
                                      OOXMLPart embedded,
                                      int depth,
                                      String location,
                                      Context context) {
        byte[] data = embedded.getData();

        if (depth >= maxDepth) {
            markUninspectable(outer, embedded, location,
                    "Nested embedded-package depth exceeded " + maxDepth,
                    context,
                    "Remove the containing embedded package.");
            return;
        }

        if (data.length > maxEmbeddedBytes) {
            markUninspectable(outer, embedded, location,
                    "Embedded package exceeds the recursive inspection limit: " + data.length + " bytes",
                    context,
                    "Remove the containing embedded package.");
            return;
        }

        // Direct embedded OOXML package.
        if (looksLikeOOXMLZip(data)) {
            if (context.packagesInspected >= maxEmbeddedPackages) {
                markUninspectable(outer, embedded, location,
                        "Embedded package count exceeded " + maxEmbeddedPackages,
                        context,
                        "Remove the containing embedded package.");
                return;
            }

            context.packagesInspected++;
            try {
                OOXMLPackage nested = reader.read(new ByteArrayInputStream(data));
                List<SecurityFinding> nestedFindings = analyze(nested);
                appendFindings(context.findings, nestedFindings, location);

                // First recursively sanitize embedded packages carried by the
                // nested package. This gives the inner document the same CDR
                // treatment as the outer document.
                sanitizePackageEmbeddings(nested, depth + 1, location, context);

                // Then sanitize the nested package's own active/external
                // content using the common policy.
                List<String> nestedActions = sanitizer.sanitize(nested, nestedFindings);
                context.actions.addAll(prefixActions(nestedActions, location));

                List<SecurityFinding> remaining = analyze(nested);
                boolean blocking = hasBlockingFinding(remaining);
                if (blocking) {
                    removeContainingPart(outer, embedded, context,
                            "Nested OOXML package remains unsafe after recursive sanitization: " +
                                    firstBlocking(remaining));
                    return;
                }

                byte[] sanitized = writer.writeToBytes(nested);
                embedded.setData(sanitized);
                context.actions.add("Reconstructed and preserved sanitized embedded OOXML package: " + location);
                return;
            } catch (Exception ex) {
                markUninspectable(outer, embedded, location,
                        "Embedded OOXML package could not be safely parsed or reconstructed: " + safeMessage(ex),
                        context,
                        "Remove the containing embedded package.");
                return;
            }
        }

        // OLE can contain an OOXML Package stream. We can safely inspect that
        // nested boundary, but rewriting an arbitrary OLE compound file is a
        // separate package-level operation. If a nested OOXML threat is found
        // inside OLE, remove the unsafe OLE boundary rather than attempting
        // byte-level surgery inside an opaque container.
        if (looksLikeOle(data)) {
            if (containsUnsafeOOXMLInsideOle(data, depth + 1, location, context)) {
                removeContainingPart(outer, embedded, context,
                        "Unsafe OOXML content detected inside OLE; OLE boundary is not rewritten in-place.");
            }
        }
    }

    private List<SecurityFinding> analyze(OOXMLPackage pkg) {
        String format = detectFormat(pkg);
        List<SecurityFinding> findings = new ArrayList<>();
        switch (format) {
            case "PPTX":
                findings.addAll(new PPTXThreatAnalyzer().analyze(pkg));
                break;
            case "DOCX":
                findings.addAll(new DOCXThreatAnalyzer().analyze(pkg));
                break;
            case "XLSX":
                findings.addAll(new XLSXThreatAnalyzer().analyze(pkg));
                break;
            default:
                findings.addAll(commonAnalyzer.analyze(pkg));
                break;
        }
        return findings;
    }

    private String detectFormat(OOXMLPackage pkg) {
        if (pkg.hasPart("ppt/presentation.xml")) return "PPTX";
        if (pkg.hasPart("word/document.xml")) return "DOCX";
        if (pkg.hasPart("xl/workbook.xml")) return "XLSX";
        return "OOXML";
    }

    private boolean isEmbeddedCandidate(OOXMLPart part) {
        String name = part.getPartName().toLowerCase(Locale.ROOT);
        String type = part.getContentType() == null ? "" : part.getContentType().toLowerCase(Locale.ROOT);
        return name.contains("/embeddings/") ||
                type.contains("embeddedpackage") ||
                type.contains("oleobject");
    }

    private boolean looksLikeOOXMLZip(byte[] data) {
        if (data == null || data.length < 4) return false;
        boolean zipMagic = (data[0] == 'P' && data[1] == 'K' &&
                ((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6)));
        if (!zipMagic) return false;

        boolean contentTypes = false;
        boolean rootRels = false;
        int count = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++count > maxZipEntries) return false;
                if (entry.isDirectory()) continue;
                String name = entry.getName().replace('\\', '/');
                if ("[Content_Types].xml".equalsIgnoreCase(name)) contentTypes = true;
                if ("_rels/.rels".equalsIgnoreCase(name)) rootRels = true;
                if (contentTypes && rootRels) return true;
            }
        } catch (IOException ignored) {
            return false;
        }
        return false;
    }

    private boolean looksLikeOle(byte[] data) {
        return data != null && data.length >= 8 &&
                (data[0] & 0xff) == 0xD0 && (data[1] & 0xff) == 0xCF &&
                (data[2] & 0xff) == 0x11 && (data[3] & 0xff) == 0xE0 &&
                (data[4] & 0xff) == 0xA1 && (data[5] & 0xff) == 0xB1 &&
                (data[6] & 0xff) == 0x1A && (data[7] & 0xff) == 0xE1;
    }

    private boolean containsUnsafeOOXMLInsideOle(byte[] data,
                                                  int depth,
                                                  String location,
                                                  Context context) {
        // Avoid a dependency on OLE stream rewriting. We inspect candidate
        // streams only; ordinary OLE streams are left untouched.
        try (org.apache.poi.poifs.filesystem.POIFSFileSystem fs =
                     new org.apache.poi.poifs.filesystem.POIFSFileSystem(new ByteArrayInputStream(data))) {
            return inspectOleDirectory(fs.getRoot(), depth, location, context);
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean inspectOleDirectory(org.apache.poi.poifs.filesystem.DirectoryNode directory,
                                        int depth,
                                        String location,
                                        Context context) {
        for (org.apache.poi.poifs.filesystem.Entry entry : directory) {
            if (entry instanceof org.apache.poi.poifs.filesystem.DirectoryNode) {
                if (inspectOleDirectory((org.apache.poi.poifs.filesystem.DirectoryNode) entry,
                        depth, location + "!" + entry.getName(), context)) return true;
                continue;
            }
            try (org.apache.poi.poifs.filesystem.DocumentInputStream in =
                         directory.createDocumentInputStream(entry)) {
                byte[] stream = readBounded(in, maxEmbeddedBytes);
                if (!looksLikeOOXMLZip(stream)) continue;
                if (depth >= maxDepth) {
                    context.limitReached = true;
                    return true;
                }
                OOXMLPackage nested = reader.read(new ByteArrayInputStream(stream));
                List<SecurityFinding> nestedFindings = analyze(nested);
                appendFindings(context.findings, nestedFindings,
                        location + "!" + entry.getName());
                if (hasBlockingFinding(nestedFindings)) return true;
            } catch (Exception ignored) {
                // Non-OOXML OLE streams are handled by the normal OLE analyzer.
            }
        }
        return false;
    }

    private byte[] readBounded(org.apache.poi.poifs.filesystem.DocumentInputStream in,
                               long max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > max) throw new IOException("OLE stream exceeds inspection limit");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private void markUninspectable(OOXMLPackage outer,
                                   OOXMLPart part,
                                   String location,
                                   String evidence,
                                   Context context,
                                   String action) {
        context.limitReached = true;
        if (context.findings != null) {
            context.findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.SUSPICIOUS_ARCHIVE,
                    ThreatSeverity.CRITICAL,
                    part,
                    null,
                    null,
                    evidence + " at " + location,
                    "Embedded content could not be safely inspected within the configured security budget.",
                    action
            ));
        }
        removeContainingPart(outer, part, context, evidence);
    }

    private void removeContainingPart(OOXMLPackage outer,
                                      OOXMLPart embedded,
                                      Context context,
                                      String reason) {
        String name = embedded.getPartName();
        List<OOXMLRelationship> incoming = new ArrayList<>();
        for (model.ooxml.OOXMLRelationship r : outer.getRelationships()) {
            if (r == null || r.isExternal() || r.getTarget() == null) continue;
            String resolved = resolveTarget(r.getSourcePart(), r.getTarget());
            if (name.equals(resolved)) incoming.add(r);
        }
        for (model.ooxml.OOXMLRelationship r : incoming) {
            if (outer.removeRelationship(r.getSourcePart(), r.getId())) {
                removeRelationshipReference(outer, r.getSourcePart(), r.getId(), context);
            }
        }
        outer.removeRelationshipsFrom(name);
        outer.removeRelationshipsTargeting(name);
        outer.removePart(name);
        outer.removeContentType(name);
        outer.removeContentType("/" + name);
        context.actions.add("Removed unsafe embedded package " + name + ": " + reason);
    }

    private void removeRelationshipReference(OOXMLPackage pkg,
                                             String sourcePart,
                                             String relationshipId,
                                             Context context) {
        if (sourcePart == null || relationshipId == null) return;
        OOXMLPart source = pkg.getPart(sourcePart);
        if (source == null || source.getData() == null || !isXmlPart(source)) return;

        String xml = new String(source.getData(), java.nio.charset.StandardCharsets.UTF_8);
        String quoted = java.util.regex.Pattern.quote(relationshipId);
        String original = xml;
        String selfClosing = "(?is)<(?:[A-Za-z_][\\w.-]*:)?[A-Za-z_][\\w.-]*\\b[^>]*\\b(?:r:id|r:embed|r:link)\\s*=\\s*\"" + quoted + "\"[^>]*/>";
        xml = xml.replaceAll(selfClosing, "");
        xml = xml.replaceAll("(?i)\\s+(?:r:id|r:embed|r:link)\\s*=\\s*[\"']" + quoted + "[\"']", "");
        if (!xml.equals(original)) {
            source.setData(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            context.actions.add("Removed XML reference to relationship " + relationshipId + " in " + sourcePart);
        }
    }

    private boolean isXmlPart(OOXMLPart part) {
        String name = part.getPartName() == null ? "" : part.getPartName().toLowerCase(Locale.ROOT);
        return part.isXml() || name.endsWith(".xml") || name.endsWith(".rels");
    }

    private String resolveTarget(String sourcePart, String target) {
        String t = target.replace('\\', '/').trim();
        if (t.startsWith("/")) return normalize(t);
        if (sourcePart == null || sourcePart.isBlank()) return normalize(t);
        String source = sourcePart.replace('\\', '/');
        int slash = source.lastIndexOf('/');
        String dir = slash < 0 ? "" : source.substring(0, slash);
        return normalize(dir.isEmpty() ? t : dir + "/" + t);
    }

    private String normalize(String path) {
        String[] pieces = path.split("/");
        List<String> result = new ArrayList<>();
        for (String p : pieces) {
            if (p.isEmpty() || ".".equals(p)) continue;
            if ("..".equals(p)) {
                if (!result.isEmpty()) result.remove(result.size() - 1);
            } else result.add(p);
        }
        return String.join("/", result);
    }

    private boolean hasBlockingFinding(Collection<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding f : findings) {
            if (f != null && (f.getClassification() == FindingClassification.THREAT ||
                    f.getClassification() == FindingClassification.POLICY_VIOLATION)) return true;
        }
        return false;
    }

    private String firstBlocking(Collection<SecurityFinding> findings) {
        if (findings != null) {
            for (SecurityFinding f : findings) {
                if (f != null && (f.getClassification() == FindingClassification.THREAT ||
                        f.getClassification() == FindingClassification.POLICY_VIOLATION)) {
                    return f.getType() + " at " + f.getPartName();
                }
            }
        }
        return "unknown nested threat";
    }

    private void appendFindings(List<SecurityFinding> target,
                                List<SecurityFinding> nested,
                                String location) {
        if (target == null || nested == null) return;
        for (SecurityFinding f : nested) {
            if (f == null) continue;
            target.add(f);
        }
    }

    private List<String> prefixActions(List<String> actions, String location) {
        if (actions == null || actions.isEmpty()) return List.of();
        List<String> result = new ArrayList<>(actions.size());
        for (String action : actions) {
            result.add("[embedded " + location + "] " + action);
        }
        return result;
    }

    private String safeMessage(Exception ex) {
        String message = ex.getMessage();
        return message == null || message.isBlank() ? ex.getClass().getSimpleName() : message;
    }


    private static final class Counter {
        private int packages;
    }

    public static final class Result {
        private final List<String> actions;
        private final int packagesInspected;
        private final boolean limitReached;

        private Result(List<String> actions, int packagesInspected, boolean limitReached) {
            this.actions = List.copyOf(actions);
            this.packagesInspected = packagesInspected;
            this.limitReached = limitReached;
        }

        public List<String> getActions() { return actions; }
        public int getPackagesInspected() { return packagesInspected; }
        public boolean isLimitReached() { return limitReached; }
    }

    private static final class Context {
        private final List<SecurityFinding> findings;
        private final List<String> actions;
        private int packagesInspected;
        private boolean limitReached;

        private Context(List<SecurityFinding> findings, List<String> actions) {
            this.findings = findings;
            this.actions = actions;
        }
    }
}
