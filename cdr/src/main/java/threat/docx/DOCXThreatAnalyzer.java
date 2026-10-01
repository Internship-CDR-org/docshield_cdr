package threat.docx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import threat.ooxml.OLEAnalyzer;
import threat.ooxml.OOXMLThreatAnalyzer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * DOCX-specific security analyzer layered on the common OOXML analyzer.
 * It identifies Word field/settings semantics that cannot safely be inferred
 * from package-level relationships alone.
 */
public final class DOCXThreatAnalyzer {
    private final OOXMLThreatAnalyzer commonAnalyzer = new OOXMLThreatAnalyzer();

    private static final Pattern DDE_FIELD = Pattern.compile(
            "(?is)<(?:w:)?fldSimple\\b[^>]*\\b(?:instr|instrText)\\s*=\\s*[\\\"'][^\\\"']*\\bDDE(?:AUTO)?\\b[^\\\"']*[\\\"'][^>]*>.*?</(?:w:)?fldSimple\\s*>|" +
            "<(?:w:)?instrText\\b[^>]*>.*?\\bDDE(?:AUTO)?\\b.*?</(?:w:)?instrText\\s*>"
    );
    private static final Pattern DDE_TOKEN = Pattern.compile("(?i)\\bDDE(?:AUTO)?\\b");
    private static final Pattern INSTR_TEXT = Pattern.compile("(?is)<(?:w:)?instrText\\b[^>]*>(.*?)</(?:w:)?instrText\\s*>");
    private static final Pattern EXTERNAL_FIELD = Pattern.compile(
            "(?is)\\b(?:INCLUDE|INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\\b"
    );
    private static final Pattern ACTIVE_WORD_FIELD = Pattern.compile(
            "(?is)\\b(?:MACROBUTTON|DDE|DDEAUTO)\\b"
    );
    private static final Pattern DANGEROUS_HYPERLINK_FIELD = Pattern.compile(
            "(?is)\\bHYPERLINK\\s+(?:\\x22|\\x27)?(?:file:|javascript:|vbscript:|data:|ms-|shell:|mk:)[^\\s\\x22\\x27]*"
    );
    private static final Pattern UPDATE_FIELDS = Pattern.compile(
            "(?is)<(?:w:)?updateFields\\b[^>]*\\bw:val\\s*=\\s*[\\\"']true[\\\"'][^>]*/?>"
    );
    private static final Pattern MAIL_MERGE = Pattern.compile(
            "(?is)<(?:w:)?mailMerge\\b.*?</(?:w:)?mailMerge\\s*>"
    );

    public List<SecurityFinding> analyze(OOXMLPackage packageData) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (packageData == null) return findings;

        findings.addAll(commonAnalyzer.analyze(packageData));
        findings.addAll(new OLEAnalyzer().analyze(packageData));

        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null || part.getData() == null) continue;
            String name = part.getPartName().toLowerCase(Locale.ROOT);
            if (!name.startsWith("word/") || !isXml(part)) continue;

            String xml = new String(part.getData(), StandardCharsets.UTF_8);

            String fieldInstructions = collectWordFieldInstructions(xml);
            String normalizedFieldInstructions = fieldInstructions.replaceAll("\\s+", "");
            if (DDE_TOKEN.matcher(fieldInstructions).find() || containsAnyToken(normalizedFieldInstructions, "DDE", "DDEAUTO")) {
                if (!hasFinding(findings, part.getPartName(), ThreatType.DDE)) {
                    add(findings, FindingClassification.THREAT, ThreatType.DDE,
                            ThreatSeverity.CRITICAL, part,
                            "Word DDE/DDEAUTO field construct detected in " + name,
                            "Word field codes can invoke or communicate with external applications through Dynamic Data Exchange.",
                            "Remove only the unsafe field instruction while preserving cached/displayed result content where possible.");
                }
            }

            if (ACTIVE_WORD_FIELD.matcher(fieldInstructions).find() &&
                    containsAnyToken(normalizedFieldInstructions, "MACROBUTTON")) {
                if (!hasFinding(findings, part.getPartName(), ThreatType.DANGEROUS_ACTION)) {
                    add(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_ACTION,
                            ThreatSeverity.CRITICAL, part,
                            "Word MACROBUTTON field detected in " + name,
                            "A MACROBUTTON field can invoke a Word macro when activated by the user.",
                            "Remove only the MACROBUTTON field instruction while preserving surrounding visible content.");
                }
            }

            if (DANGEROUS_HYPERLINK_FIELD.matcher(fieldInstructions).find()) {
                if (!hasFinding(findings, part.getPartName(), ThreatType.DANGEROUS_URI)) {
                    add(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_URI,
                            ThreatSeverity.CRITICAL, part,
                            "Dangerous URI inside a Word HYPERLINK field in " + name,
                            "The Word field contains a file/script/application URI that should not be retained as an active field instruction.",
                            "Remove the unsafe HYPERLINK field instruction while preserving cached/displayed text where possible.");
                }
            }

            if (EXTERNAL_FIELD.matcher(fieldInstructions).find() || containsAnyToken(normalizedFieldInstructions, "INCLUDE", "INCLUDETEXT", "INCLUDEPICTURE", "LINK", "IMPORT")) {
                if (!hasFinding(findings, part.getPartName(), ThreatType.EXTERNAL_RESOURCE)) {
                    add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_RESOURCE,
                            ThreatSeverity.HIGH, part,
                            "Word external field code detected in " + name,
                            "The document contains an INCLUDE/INCLUDETEXT/INCLUDEPICTURE/LINK/IMPORT field capable of retrieving or linking content outside the package.",
                            "Remove only the external field instruction while preserving cached/displayed content where possible.");
                }
            }

            if (name.startsWith("word/") && isAltChunkPart(part)) {
                if (isActiveAltChunk(part)) {
                    add(findings, FindingClassification.THREAT, ThreatType.EMBEDDED_ACTIVE_CONTENT,
                            ThreatSeverity.HIGH, part,
                            "Active altChunk/imported-content part detected in " + name,
                            "Word altChunk can import HTML/XHTML/RTF or other alternative-format content into the document.",
                            "Remove the unsafe imported-content part and its relationship; do not execute or interpret the imported content.");
                } else {
                    add(findings, FindingClassification.OBSERVATION, ThreatType.EMBEDDED_PACKAGE,
                            ThreatSeverity.INFO, part,
                            "Word altChunk/imported-content part: " + name,
                            "Alternative-format imported content is present.",
                            "Preserve after safe inspection; remove only when active content is confirmed.");
                }
            }

            if (name.equals("word/settings.xml") && UPDATE_FIELDS.matcher(xml).find()) {
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.AUTO_UPDATE_FIELDS,
                        ThreatSeverity.HIGH, part,
                        "Automatic field updating is enabled in word/settings.xml",
                        "Automatically updating fields can cause external field content to be refreshed when the document opens.",
                        "Disable automatic field updating during CDR.");
            }

            if (name.equals("word/settings.xml") && MAIL_MERGE.matcher(xml).find()) {
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, part,
                        "Word mail-merge configuration is present in word/settings.xml",
                        "Mail-merge configuration can reference external data sources.",
                        "Remove the external mail-merge configuration during CDR.");
            }
        }

        analyzeDocxRelationships(packageData, findings);
        return findings;
    }

    private void analyzeDocxRelationships(OOXMLPackage pkg, List<SecurityFinding> findings) {
        for (var r : pkg.getRelationships()) {
            if (r == null) continue;
            String source = r.getSourcePart() == null ? "" : r.getSourcePart().toLowerCase(Locale.ROOT);
            String type = r.getType() == null ? "" : r.getType().toLowerCase(Locale.ROOT);
            if (!source.startsWith("word/")) continue;

            if (type.contains("attachedtemplate")) {
                String target = r.getTarget() == null ? "" : r.getTarget();
                if (r.isExternal()) {
                    addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_TEMPLATE, ThreatSeverity.CRITICAL, r,
                            "External attachedTemplate relationship: " + target,
                            "Word uses the attached template relationship to locate the associated template; an external target can load content outside the package.",
                            "Remove the attached-template relationship and its XML reference.");
                } else {
                    String resolved = resolve(pkg, r.getSourcePart(), r.getTarget());
                    OOXMLPart targetPart = resolved == null ? null : pkg.getPart(resolved);
                    String targetCt = targetPart == null || targetPart.getContentType() == null ? "" : targetPart.getContentType().toLowerCase(Locale.ROOT);
                    if (targetCt.contains("macroenabled") || (resolved != null && resolved.toLowerCase(Locale.ROOT).endsWith(".dotm"))) {
                        findings.add(new SecurityFinding(FindingClassification.THREAT, ThreatType.EXTERNAL_TEMPLATE,
                                ThreatSeverity.CRITICAL, targetPart, r.getSourcePart(), r.getId(),
                                "Macro-enabled attached template: " + resolved,
                                "The attached Word template is macro-enabled and can introduce active content into the document context.",
                                "Remove the attached-template relationship and the unsafe template part."));
                    } else {
                        addRel(findings, FindingClassification.OBSERVATION, ThreatType.EXTERNAL_TEMPLATE, ThreatSeverity.INFO, r,
                                "Internal attached template: " + target,
                                "A local attached template is present.",
                                "Preserve after inspection when it is not macro-enabled or otherwise unsafe.");
                    }
                }
            } else if (type.endsWith("/afchunk")) {
                if (r.isExternal()) {
                    addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_RESOURCE, ThreatSeverity.HIGH, r,
                            "External altChunk relationship: " + r.getTarget(),
                            "The document imports alternative-format content from outside the package.",
                            "Remove the external altChunk relationship.");
                } else {
                    String resolved = resolve(pkg, r.getSourcePart(), r.getTarget());
                    OOXMLPart targetPart = resolved == null ? null : pkg.getPart(resolved);
                    if (targetPart != null && isActiveAltChunk(targetPart)) {
                        findings.add(new SecurityFinding(FindingClassification.THREAT, ThreatType.EMBEDDED_ACTIVE_CONTENT,
                                ThreatSeverity.HIGH, targetPart, r.getSourcePart(), r.getId(),
                                "Active internal altChunk content: " + resolved,
                                "The Word document imports alternative-format content containing active HTML/script or macro-enabled content.",
                                "Remove the unsafe altChunk relationship and target part."));
                    } else if (targetPart != null) {
                        findings.add(new SecurityFinding(FindingClassification.OBSERVATION, ThreatType.EMBEDDED_PACKAGE,
                                ThreatSeverity.INFO, targetPart, r.getSourcePart(), r.getId(),
                                "Internal altChunk content: " + resolved,
                                "Word imports alternative-format content from an internal package part.",
                                "Preserve after safe inspection."));
                    }
                }
            } else if (type.contains("mailmergesource")) {
                addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_CONNECTION, ThreatSeverity.HIGH, r,
                        "Word mail-merge data-source relationship: " + r.getTarget(),
                        "The document has a relationship to a mail-merge data source.",
                        "Remove the external data-source relationship and its XML reference during CDR.");
            } else if (type.contains("recipientdata")) {
                addRel(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION, ThreatSeverity.MEDIUM, r,
                        "Word mail-merge recipient-data relationship: " + r.getTarget(),
                        "Mail-merge recipient data is part of external-data workflow state.",
                        "Remove the recipient-data relationship/configuration during CDR.");
            }
        }
    }

    private String resolve(OOXMLPackage pkg, String source, String target) {
        if (target == null || target.isBlank()) return null;
        String t = target.replace('\\', '/');
        if (t.startsWith("/")) return t.substring(1);
        String s = source == null ? "" : source.replace('\\', '/');
        int slash = s.lastIndexOf('/');
        String base = slash < 0 ? "" : s.substring(0, slash);
        java.util.ArrayList<String> pieces = new java.util.ArrayList<>();
        for (String p : (base.isEmpty() ? t : base + "/" + t).split("/")) {
            if (p.isEmpty() || p.equals(".")) continue;
            if (p.equals("..")) { if (!pieces.isEmpty()) pieces.remove(pieces.size()-1); continue; }
            pieces.add(p);
        }
        return String.join("/", pieces);
    }

    private void addRel(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                        ThreatSeverity s, model.ooxml.OOXMLRelationship r, String evidence,
                        String description, String action) {
        out.add(new SecurityFinding(c, t, s, null, r.getSourcePart(), r.getId(), evidence, description, action));
    }

    private String collectWordFieldInstructions(String xml) {
        StringBuilder instructions = new StringBuilder();
        Matcher matcher = INSTR_TEXT.matcher(xml);
        while (matcher.find()) {
            instructions.append(matcher.group(1)).append(' ');
        }
        Pattern simple = Pattern.compile("(?is)<(?:w:)?fldSimple\\b[^>]*\\b(?:w:)?instr\\s*=\\s*[\"']([^\"']*)[\"']");
        Matcher simpleMatcher = simple.matcher(xml);
        while (simpleMatcher.find()) instructions.append(simpleMatcher.group(1)).append(' ');
        return instructions.toString();
    }

    private boolean containsAnyToken(String normalized, String... tokens) {
        if (normalized == null) return false;
        String value = normalized.toUpperCase(Locale.ROOT);
        for (String token : tokens) {
            if (token != null && value.contains(token.toUpperCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private boolean hasFinding(List<SecurityFinding> findings, String partName, ThreatType type) {
        for (SecurityFinding f : findings) {
            if (f != null && f.getType() == type && java.util.Objects.equals(f.getPartName(), partName)) return true;
        }
        return false;
    }

    private boolean isAltChunkPart(OOXMLPart part) {
        String ct = part.getContentType() == null ? "" : part.getContentType().toLowerCase(Locale.ROOT);
        return ct.contains("text/html") || ct.contains("xhtml") || ct.contains("rtf") ||
                ct.contains("message/rfc822");
    }

    private boolean isActiveAltChunk(OOXMLPart part) {
        String ct = part.getContentType() == null ? "" : part.getContentType().toLowerCase(Locale.ROOT);
        if (ct.contains("macroenabled")) return true;
        if (ct.contains("text/html") || ct.contains("xhtml")) {
            String text = new String(part.getData() == null ? new byte[0] : part.getData(), StandardCharsets.UTF_8);
            return Pattern.compile("(?is)<\\s*(script|object|embed|iframe|form)\\b|javascript\\s*:|vbscript\\s*:").matcher(text).find();
        }
        return false;
    }

    private boolean isXml(OOXMLPart part) {
        String name = part.getPartName().toLowerCase(Locale.ROOT);
        return part.isXml() || name.endsWith(".xml") || name.endsWith(".rels");
    }

    private void add(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                     ThreatSeverity s, OOXMLPart part, String evidence,
                     String description, String action) {
        out.add(new SecurityFinding(c, t, s, part, null, null,
                evidence, description, action));
    }
}
