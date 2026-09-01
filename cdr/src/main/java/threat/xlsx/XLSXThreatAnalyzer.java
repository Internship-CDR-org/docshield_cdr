package threat.xlsx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import threat.ooxml.OOXMLThreatAnalyzer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Excel-specific threat analysis layered on the common OOXML analyzer.
 *
 * The analyzer is capability based: it identifies Excel structures that can
 * execute code, resolve external workbook/data sources, invoke active
 * formula functions, or carry legacy macro content. Ordinary hyperlinks and
 * ordinary formulas are preserved as observations rather than treated as
 * malware.
 */
public final class XLSXThreatAnalyzer {

    private static final Pattern EXTERNAL_WORKBOOK_FORMULA = Pattern.compile(
            "(?is)(?:^|[^A-Za-z0-9_])(?:'[^']*'|[^\\s,;()]+)?\\[[^\\]]+\\][^!\\s]+!"
    );
    private static final Pattern DDE_FORMULA = Pattern.compile(
            "(?is)(?:\\[[^\\]]+\\])?[^\\s,;()]+(?:\\.exe|\\.com|\\.bat|\\.cmd)?\\|[^!\\s]+!"
    );
    private static final Pattern ACTIVE_FORMULA = Pattern.compile(
            "(?is)(?:^|[^A-Za-z0-9_])(RTD|WEBSERVICE|FILTERXML|HYPERLINK|CALL|REGISTER\\.ID|EXEC|RUN|GET\\.CELL|GET\\.WORKBOOK)\\s*\\("
    );
    private static final Pattern DANGEROUS_HYPERLINK_URI = Pattern.compile(
            "(?is)HYPERLINK\\s*\\(\\s*[\"']\\s*(?:file:|javascript:|vbscript:|data:|ms-|shell:|mk:|\\\\\\\\|/\\\\)"
    );
    private static final Pattern DANGEROUS_CONNECTION_XML = Pattern.compile(
            "(?is)<(?:[^:>]+:)?(?:webPr|dbPr|textPr|olapPr|parameters|parameter)\\b|\\b(?:odbc|oledb|oleDb|provider|command|connectionString|url|server)\\s*="
    );
    private static final Pattern XLM_ACTIVE = Pattern.compile(
            "(?is)<(?:[^:>]+:)?(?:f|formula|macro)\\b[^>]*>(?:[^<]*\\b(?:EXEC|CALL|RUN|REGISTER|GET\\.DOCUMENT|WEBSERVICE)\\b|[^<]*\\b(?:DDE|DDEAUTO)\\b)"
    );
    private static final Pattern EXTERNAL_URL = Pattern.compile(
            "(?i)\\b(?:https?|ftp|file|ms-|javascript|vbscript|data):"
    );

    private final OOXMLThreatAnalyzer common = new OOXMLThreatAnalyzer();

    public List<SecurityFinding> analyze(OOXMLPackage packageData) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (packageData == null) return findings;

        findings.addAll(common.analyze(packageData));
        analyzeExcelParts(packageData, findings);
        analyzeExcelRelationships(packageData, findings);
        deduplicate(findings);
        return findings;
    }

    private void analyzeExcelParts(OOXMLPackage pkg, List<SecurityFinding> findings) {
        for (OOXMLPart part : pkg.getParts()) {
            if (part == null || part.getPartName() == null) continue;
            String name = part.getPartName().toLowerCase(Locale.ROOT);
            String ct = lower(part.getContentType());
            String xml = isXmlLike(name, part) ? text(part.getData()) : "";

            if (isXlmPart(name, ct)) {
                add(findings, FindingClassification.THREAT, ThreatType.XLM_MACRO,
                        ThreatSeverity.CRITICAL, part,
                        "Excel legacy macro-sheet part: " + name,
                        "Excel 4.0/XLM macro sheets can contain executable macro instructions.",
                        "Remove the macro-sheet part and all relationships to it.");
            }

            if (isExternalLinkPart(name, ct)) {
                // The externalLink part is an Excel workbook/data-source boundary.
                // It is not an ordinary user hyperlink.
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_WORKBOOK,
                        ThreatSeverity.HIGH, part,
                        "Excel external-link part: " + name,
                        "The workbook contains an external workbook/data-source link that Excel may resolve or calculate.",
                        "Remove the external-link part and external workbook references; preserve ordinary hyperlinks.");

                String lowerXml = xml.toLowerCase(Locale.ROOT);
                if (lowerXml.contains("ddelink") || lowerXml.contains("olelink") ||
                        XLM_ACTIVE.matcher(xml).find()) {
                    add(findings, FindingClassification.THREAT, ThreatType.DDE,
                            ThreatSeverity.CRITICAL, part,
                            "DDE/OLE-style external link structure in " + name,
                            "The external-link part carries a DDE/OLE data-source capability.",
                            "Remove the external-link boundary and its relationships.");
                }
            }

            if (isConnectionPart(name, ct)) {
                FindingClassification c = DANGEROUS_CONNECTION_XML.matcher(xml).find()
                        ? FindingClassification.THREAT : FindingClassification.POLICY_VIOLATION;
                ThreatSeverity sev = c == FindingClassification.THREAT ? ThreatSeverity.CRITICAL : ThreatSeverity.HIGH;
                add(findings, c, ThreatType.EXTERNAL_CONNECTION, sev, part,
                        "Excel external data connection: " + name,
                        "External connections can retrieve data through providers, servers, commands, web queries, or other external sources.",
                        "Remove the external connection/query configuration and its relationships.");
            }

            if (isQueryTablePart(name, ct)) {
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, part,
                        "Excel query-table structure: " + name,
                        "Query tables can refresh data from an external source.",
                        "Remove the query-table configuration and its external relationships.");
            }

            if (isXmlLike(name, part) && name.startsWith("xl/")) {
                analyzeFormulaElements(part, xml, findings);
                analyzeDefinedNames(part, xml, findings);
            }
        }
    }

    private static final Pattern FORMULA_ELEMENT = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?f\\b[^>]*>(.*?)</(?:[A-Za-z_][\\w.-]*:)?f\\s*>"
    );
    private static final Pattern DEFINED_NAME_ELEMENT = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?definedName\\b[^>]*>(.*?)</(?:[A-Za-z_][\\w.-]*:)?definedName\\s*>"
    );

    private void analyzeFormulaElements(OOXMLPart part, String xml, List<SecurityFinding> findings) {
        Matcher m = FORMULA_ELEMENT.matcher(xml);
        while (m.find()) {
            analyzeFormulaText(part, m.group(1), findings, "formula in " + part.getPartName());
        }
    }

    private void analyzeDefinedNames(OOXMLPart part, String xml, List<SecurityFinding> findings) {
        Matcher m = DEFINED_NAME_ELEMENT.matcher(xml);
        while (m.find()) {
            analyzeFormulaText(part, m.group(1), findings, "defined name in " + part.getPartName());
        }
    }

    private void analyzeFormulaText(OOXMLPart part, String rawFormula,
                                    List<SecurityFinding> findings, String location) {
        String formula = rawFormula == null ? "" : rawFormula;
        String normalized = formula.replace("&quot;", "\"").replace("&amp;", "&");

        if (DDE_FORMULA.matcher(normalized).find() || Pattern.compile("(?i)\\bDDE(?:AUTO)?\\b").matcher(normalized).find()) {
            add(findings, FindingClassification.THREAT, ThreatType.DDE, ThreatSeverity.CRITICAL, part,
                    "DDE-style formula detected: " + normalized,
                    "The Excel formula contains a DDE/DDEAUTO-style external execution/data-resolution construct.",
                    "Remove the active formula while preserving a cached value where possible.");
        }

        if (EXTERNAL_WORKBOOK_FORMULA.matcher(normalized).find()) {
            add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_WORKBOOK,
                    ThreatSeverity.HIGH, part,
                    "External workbook reference detected: " + normalized,
                    "The formula references another workbook/data source.",
                    "Remove the external formula/reference while preserving its cached value where possible.");
        }

        Matcher active = ACTIVE_FORMULA.matcher(normalized);
        while (active.find()) {
            String fn = active.group(1).toUpperCase(Locale.ROOT);
            if ("HYPERLINK".equals(fn)) {
                if (DANGEROUS_HYPERLINK_URI.matcher(normalized).find()) {
                    add(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_URI,
                            ThreatSeverity.HIGH, part,
                            "Dangerous HYPERLINK URI detected: " + normalized,
                            "The HYPERLINK formula contains a file/script/application URI.",
                            "Remove the dangerous formula while preserving its cached/displayed result where possible.");
                }
            } else if ("RTD".equals(fn) || "CALL".equals(fn) || "REGISTER.ID".equals(fn) ||
                    "EXEC".equals(fn) || "RUN".equals(fn) || "GET.CELL".equals(fn) || "GET.WORKBOOK".equals(fn)) {
                add(findings, FindingClassification.THREAT, ThreatType.ACTIVE_FORMULA,
                        ThreatSeverity.CRITICAL, part,
                        "Active Excel formula function " + fn + " detected in " + location,
                        "The formula can invoke external automation, native functions, or macro-like behavior.",
                        "Remove the active formula while preserving its cached value where possible.");
            } else if ("WEBSERVICE".equals(fn) || "FILTERXML".equals(fn)) {
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.ACTIVE_FORMULA,
                        ThreatSeverity.HIGH, part,
                        "External-data formula function " + fn + " detected in " + location,
                        "The formula can retrieve or process external web/XML content.",
                        "Remove the external-data formula while preserving its cached value where possible.");
            }
        }
    }

    private void analyzeExcelRelationships(OOXMLPackage pkg, List<SecurityFinding> findings) {
        for (OOXMLRelationship r : pkg.getRelationships()) {
            if (r == null) continue;
            String type = lower(r.getType());
            String target = r.getTarget() == null ? "" : r.getTarget().trim();
            String source = r.getSourcePart() == null ? "" : r.getSourcePart().toLowerCase(Locale.ROOT);

            if (type.contains("externallink")) {
                addRel(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_WORKBOOK,
                        ThreatSeverity.HIGH, r,
                        "Excel externalLink relationship: " + target,
                        "The workbook has a relationship to an external workbook/data-source part.",
                        "Remove the external-link relationship and its target part.");
            }

            if (type.endsWith("/connections") || type.contains("connection")) {
                addRel(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, r,
                        "Excel connection relationship: " + target,
                        "The workbook references an external data connection configuration.",
                        "Remove the connection relationship and associated configuration.");
            }

            if (type.contains("querytable")) {
                addRel(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, r,
                        "Excel query-table relationship: " + target,
                        "The workbook references a query-table structure capable of external refresh.",
                        "Remove the query-table relationship/configuration.");
            }

            if (type.contains("activex") || type.endsWith("/control") || type.contains("controlbinary")) {
                addRel(findings, FindingClassification.THREAT, ThreatType.ACTIVEX_OBJECT,
                        ThreatSeverity.HIGH, r,
                        "Excel ActiveX/control relationship: " + target,
                        "The relationship identifies an interactive ActiveX/control object.",
                        "Remove the control relationship and associated parts.");
            }

            if (type.endsWith("/oleobject") || type.contains("oleobject")) {
                addRel(findings, FindingClassification.OBSERVATION, ThreatType.OLE_OBJECT,
                        ThreatSeverity.INFO, r,
                        "Excel OLE relationship: " + target,
                        "An OLE object is embedded in the workbook and requires payload inspection.",
                        "Preserve unless the OLE payload is confirmed unsafe.");
            }

            if (source.startsWith("xl/") && r.isExternal() && !type.contains("hyperlink")) {
                if (looksLikeDangerousUri(target)) {
                    addRel(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_URI,
                            ThreatSeverity.CRITICAL, r,
                            "Dangerous Excel external URI: " + target,
                            "The relationship targets a file/script/application/data URI.",
                            "Remove the external relationship.");
                }
            }
        }
    }

    private boolean isXlmPart(String name, String ct) {
        return name.startsWith("xl/macrosheets/") || name.startsWith("xl/dialogsheets/") ||
                ct.contains("macrosheet") || ct.contains("dialogsheet");
    }

    private boolean isExternalLinkPart(String name, String ct) {
        return name.startsWith("xl/externallinks/") || ct.contains("externallink");
    }

    private boolean isConnectionPart(String name, String ct) {
        return name.equals("xl/connections.xml") || ct.contains("connections");
    }

    private boolean isQueryTablePart(String name, String ct) {
        return name.startsWith("xl/querytables/") || name.startsWith("xl/queries/") || ct.contains("querytable") || ct.contains("query");
    }

    private boolean isXmlLike(String name, OOXMLPart part) {
        return part.isXml() || name.endsWith(".xml") || name.endsWith(".rels");
    }

    private String text(byte[] data) {
        return data == null ? "" : new String(data, StandardCharsets.UTF_8);
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private boolean looksLikeDangerousUri(String target) {
        String t = lower(target);
        return t.startsWith("file:") || t.startsWith("javascript:") || t.startsWith("vbscript:") ||
                t.startsWith("data:") || t.startsWith("ms-") || t.startsWith("shell:") || t.startsWith("mk:");
    }

    private void add(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                     ThreatSeverity s, OOXMLPart part, String evidence,
                     String description, String action) {
        out.add(new SecurityFinding(c, t, s, part, null, null, evidence, description, action));
    }

    private void addRel(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                        ThreatSeverity s, OOXMLRelationship r, String evidence,
                        String description, String action) {
        out.add(new SecurityFinding(c, t, s, null, r.getSourcePart(), r.getId(),
                evidence, description, action));
    }

    private void deduplicate(List<SecurityFinding> findings) {
        Set<String> seen = new HashSet<>();
        findings.removeIf(f -> {
            String key = String.valueOf(f.getType()) + "|" + String.valueOf(f.getClassification()) + "|" +
                    String.valueOf(f.getPartName()) + "|" + String.valueOf(f.getSourcePart()) + "|" +
                    String.valueOf(f.getRelationshipId()) + "|" + String.valueOf(f.getEvidence());
            return !seen.add(key);
        });
    }
}
