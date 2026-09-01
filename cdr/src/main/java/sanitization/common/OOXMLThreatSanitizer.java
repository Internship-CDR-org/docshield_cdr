package sanitization.common;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Common policy-driven sanitizer for OPC/OOXML packages.
 *
 * Format-specific processors feed findings into this class. The sanitizer
 * applies the same security policy to DOCX, XLSX and PPTX while using the
 * package graph (parts + relationships + content types) as the mutation
 * boundary.
 */
public final class OOXMLThreatSanitizer implements Sanitizer<OOXMLPackage> {

    private static final Pattern REL_REFERENCE = Pattern.compile(
            "(?i)\\b(?:r:id|r:embed|r:link)\\s*=\\s*\"([^\"]+)\""
    );

    private static final Pattern ENTITY_DECL = Pattern.compile(
            "(?is)<!ENTITY\\s+([A-Za-z_:][\\w:.-]*)\\s+(?:SYSTEM\\s+|PUBLIC\\s+)?(?:\"[^\"]*\"|'[^']*'|\\[[^]]*\\])\\s*>"
    );

    private static final Pattern CUSTOM_ENTITY_REF = Pattern.compile(
            "&([A-Za-z_:][\\w:.-]*);"
    );

    private static final Pattern DANGEROUS_PPTX_ACTION_ELEMENT = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?hlink(?:Click|Hover)\\b[^>]*(?:ppaction://(?:program|macro|ole|hlinkfile|hlinkpres)(?:[^\"\'\\s>]*)?|(?:action|actionType)\\s*=\\s*\"[^\"]*(?:runprogram|runmacro|oleverb|ppaction://(?:program|macro|ole|hlinkfile|hlinkpres))[^\"]*\")[^>]*(?:/>|>.*?</(?:[A-Za-z_][\\w.-]*:)?hlink(?:Click|Hover)\\s*>)"
    );

    private static final Pattern DANGEROUS_PPTX_ACTION_ATTRIBUTE = Pattern.compile(
            "(?i)\\s+(?:action|actionType)\\s*=\\s*\"[^\"]*(?:ppaction://(?:program|macro|ole|hlinkfile|hlinkpres)|runprogram|runmacro|oleverb)[^\"]*\""
    );

    private static final Pattern DDE_FIELD = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?fldSimple\\b[^>]*\\bDDE(?:AUTO)?\\b[^>]*>.*?</(?:[A-Za-z_][\\w.-]*:)?fldSimple\\s*>"
    );
    private static final Pattern DDE_INSTR = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?instrText\\b[^>]*>.*?\\bDDE(?:AUTO)?\\b.*?</(?:[A-Za-z_][\\w.-]*:)?instrText\\s*>"
    );
    private static final Pattern WORD_EXTERNAL_FIELD = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?fldSimple\\b[^>]*\\b(?:INCLUDE|INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\\b[^>]*>.*?</(?:[A-Za-z_][\\w.-]*:)?fldSimple\\s*>|" +
            "<(?:[A-Za-z_][\\w.-]*:)?instrText\\b[^>]*>.*?\\b(?:INCLUDE|INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\\b.*?</(?:[A-Za-z_][\\w.-]*:)?instrText\\s*>"
    );

    @Override
    public List<String> sanitize(OOXMLPackage packageData, List<SecurityFinding> findings) {
        List<String> actions = new ArrayList<>();
        if (packageData == null || findings == null) return actions;

        Set<String> removedParts = new HashSet<>();

        for (SecurityFinding finding : findings) {
            if (finding == null || finding.getType() == null) continue;

            ThreatType type = finding.getType();

            switch (type) {
                case DANGEROUS_URI:
                case EXTERNAL_TEMPLATE:
                case EXTERNAL_REFERENCE:
                case EXTERNAL_RESOURCE:
                case EXTERNAL_CONNECTION:
                case EXTERNAL_WORKBOOK:
                    if (finding.getRelationshipId() != null) {
                        removeRelationship(packageData, finding, actions);
                    }
                    if (type == ThreatType.DANGEROUS_URI && finding.getRelationshipId() == null &&
                            finding.getPartName() != null) {
                        sanitizeXmlPart(packageData, finding, actions);
                    }
                    if (finding.getPartName() != null &&
                            finding.getClassification() != threat.common.FindingClassification.OBSERVATION) {
                        if (type == ThreatType.EXTERNAL_TEMPLATE) {
                            removeUnsafePart(packageData, finding.getPartName(), actions, removedParts);
                        } else if ((type == ThreatType.EXTERNAL_RESOURCE || type == ThreatType.EXTERNAL_CONNECTION || type == ThreatType.EXTERNAL_WORKBOOK) &&
                                isDedicatedExternalPart(finding.getPartName())) {
                            removeUnsafePart(packageData, finding.getPartName(), actions, removedParts);
                        } else if (type == ThreatType.EXTERNAL_RESOURCE || type == ThreatType.EXTERNAL_CONNECTION || type == ThreatType.EXTERNAL_WORKBOOK) {
                            sanitizeXmlPart(packageData, finding, actions);
                        }
                    }
                    break;

                case DDE:
                case MALICIOUS_XML:
                case DANGEROUS_ACTION:
                case INVALID_RELATIONSHIP:
                case AUTO_UPDATE_FIELDS:
                case ACTIVE_FORMULA:
                    sanitizeXmlPart(packageData, finding, actions);
                    break;

                case VBA_PROJECT:
                case ACTIVEX_OBJECT:
                case OLE_OBJECT:
                case EMBEDDED_PACKAGE:
                case XLM_MACRO:
                case EXECUTABLE_PAYLOAD:
                case SUSPICIOUS_SVG:
                case EMBEDDED_ACTIVE_CONTENT:
                case SUSPICIOUS_ARCHIVE:
                case SUSPICIOUS_BINARY:
                    // Embedded/OLE resources are legitimate PPTX content in many
                    // presentations. Never delete an object merely because an
                    // analyzer observed its container type. Only a blocking or
                    // suspicious finding authorizes removal.
                    if (finding.getClassification() != null &&
                            finding.getClassification() != threat.common.FindingClassification.OBSERVATION) {
                        removeUnsafePart(packageData, finding.getPartName(), actions, removedParts);
                    }
                    break;

                case PATH_TRAVERSAL:
                    // A path traversal is a package-boundary violation. It
                    // should normally be rejected by the package reader. If a
                    // malformed package has nevertheless reached this stage,
                    // do not preserve the offending part.
                    removeUnsafePart(packageData, finding.getPartName(), actions, removedParts);
                    break;

                default:
                    // Observations such as normal external hyperlinks and
                    // benign images/media are intentionally preserved.
                    break;
            }
        }

        cleanupOrphanedContentTypes(packageData, removedParts, actions);
        return actions;
    }

    private void removeRelationshipReferences(OOXMLPackage pkg,
                                              String sourcePart,
                                              String id,
                                              List<String> actions) {
        if (sourcePart == null || id == null) return;

        OOXMLPart source = pkg.getPart(sourcePart);
        if (source == null || source.getData() == null || !isXmlPart(source)) return;

        String xml = new String(source.getData(), StandardCharsets.UTF_8);
        String original = xml;

        // First remove the whole relationship-bearing element. This avoids
        // leaving invalid PresentationML such as <a:blip/> or an OLE element
        // whose relationship was removed.
        xml = removeRelationshipBearingElements(xml, id);

        // Fallback for attributes on constructs for which the element pattern
        // is intentionally not recognized: remove only the relationship
        // attribute rather than leaving a stale relationship id.
        String quoted = Pattern.quote(id);
        xml = xml.replaceAll(
                "(?i)\\s+(?:r:id|r:embed|r:link)\\s*=\\s*\"" + quoted + "\"",
                ""
        );

        if (!xml.equals(original)) {
            source.setData(xml.getBytes(StandardCharsets.UTF_8));
            actions.add("Removed XML references to relationship " + id + " in " + sourcePart);
        }
    }

    private String removeRelationshipBearingElements(String xml, String id) {
        String result = xml;

        // Common self-closing relationship-bearing elements.
        String selfClosing = "(?is)<(?:[A-Za-z_][\\w.-]*:)?[A-Za-z_][\\w.-]*\\b[^>]*\\b(?:r:id|r:embed|r:link)\\s*=\\s*\""
                + Pattern.quote(id) + "\"[^>]*/>";
        result = result.replaceAll(selfClosing, "");

        // Common paired relationship-bearing elements. We use a generic
        // paired-element expression rather than rewriting the entire XML.
        String paired = "(?is)<((?:[A-Za-z_][\\w.-]*:)?[A-Za-z_][\\w.-]*)\\b[^>]*\\b(?:r:id|r:embed|r:link)\\s*=\\s*\""
                + Pattern.quote(id) + "\"[^>]*>.*?</\\1\\s*>";
        result = result.replaceAll(paired, "");

        return result;
    }

    private boolean isXmlPart(OOXMLPart part) {
        String name = part.getPartName() == null
                ? ""
                : part.getPartName().toLowerCase(Locale.ROOT);
        return part.isXml() || name.endsWith(".xml") || name.endsWith(".rels");
    }

    private void sanitizeXmlPart(OOXMLPackage pkg,
                                 SecurityFinding finding,
                                 List<String> actions) {
        String partName = finding.getPartName();
        if (partName == null || partName.isBlank()) return;

        OOXMLPart part = pkg.getPart(partName);
        if (part == null || part.getData() == null || !isXmlPart(part)) return;

        String xml = new String(part.getData(), StandardCharsets.UTF_8);
        String original = xml;

        switch (finding.getType()) {
            case DDE:
                if (partName.toLowerCase(Locale.ROOT).startsWith("word/")) {
                    // Word field instructions may be fragmented across runs.
                    // Remove only the instruction and preserve cached result text.
                    xml = stripWordFieldInstructions(xml, "DDE(?:AUTO)?");
                } else {
                    xml = DDE_FIELD.matcher(xml).replaceAll("");
                    xml = DDE_INSTR.matcher(xml).replaceAll("");
                }
                break;

            case EXTERNAL_RESOURCE:
                if (partName.toLowerCase(Locale.ROOT).startsWith("word/")) {
                    // Preserve the visible field result; remove the external
                    // field instruction itself.
                    xml = stripWordFieldInstructions(xml, "INCLUDE|INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT");
                }
                break;

            case DANGEROUS_URI:
                if (partName.toLowerCase(Locale.ROOT).startsWith("word/")) {
                    // Dangerous HYPERLINK fields are active instructions, not
                    // ordinary hyperlink relationships. Remove only the field
                    // instruction so visible/cached content can survive.
                    xml = stripWordFieldInstructions(xml, "HYPERLINK\\s+(?:\\x22|\\x27)?(?:file:|javascript:|vbscript:|data:|ms-|shell:|mk:)");
                } else if (partName.toLowerCase(Locale.ROOT).startsWith("xl/")) {
                    xml = removeExcelActiveFormulaElements(xml);
                }
                break;

            case AUTO_UPDATE_FIELDS:
                if (partName.toLowerCase(Locale.ROOT).equals("word/settings.xml")) {
                    xml = xml.replaceAll("(?is)<(?:w:)?updateFields\\b[^>]*\\bw:val\\s*=\\s*[\"']true[\"'][^>]*/?>", "");
                }
                break;

            case EXTERNAL_CONNECTION:
                if (partName.toLowerCase(Locale.ROOT).equals("word/settings.xml")) {
                    xml = xml.replaceAll("(?is)<(?:w:)?mailMerge\\b.*?</(?:w:)?mailMerge\\s*>", "");
                }
                break;

            case EXTERNAL_WORKBOOK:
                if (partName.toLowerCase(Locale.ROOT).startsWith("xl/")) {
                    xml = removeExcelExternalFormulaElements(xml);
                }
                break;

            case ACTIVE_FORMULA:
                if (partName.toLowerCase(Locale.ROOT).startsWith("xl/")) {
                    xml = removeExcelActiveFormulaElements(xml);
                }
                break;

            case DANGEROUS_ACTION:
                if (partName.toLowerCase(Locale.ROOT).startsWith("word/")) {
                    xml = stripWordFieldInstructions(xml, "MACROBUTTON");
                } else {
                    xml = removeDangerousPptxActions(pkg, partName, xml, actions);
                }
                break;

            case MALICIOUS_XML:
                xml = sanitizeXmlDeclarations(xml);
                break;

            case INVALID_RELATIONSHIP:
                if (finding.getRelationshipId() != null) {
                    String id = finding.getRelationshipId();
                    xml = removeRelationshipBearingElements(xml, id);
                    String quotedId = Pattern.quote(id);
                    xml = xml.replaceAll(
                            "(?i)\\s+(?:r:id|r:embed|r:link)\\s*=\\s*[\"']" + quotedId + "[\"']",
                            ""
                    );
                }
                break;

            default:
                break;
        }

        if (!xml.equals(original)) {
            part.setData(xml.getBytes(StandardCharsets.UTF_8));
            actions.add("Sanitized unsafe XML constructs in: " + partName);
        }
    }

    /**
     * Removes unsafe Word field instructions while preserving cached/displayed
     * field result runs. Field instructions may be fragmented across several
     * w:instrText elements, so matching one XML element is insufficient.
     */
    private String stripWordFieldInstructions(String xml, String tokenRegex) {
        if (xml == null || xml.isEmpty()) return xml;

        Pattern token = Pattern.compile("(?i)(?:" + tokenRegex + ")");
        Pattern fieldRegion = Pattern.compile(
                "(?is)<(?:w:)?fldChar[^>]*fldCharType\\s*=\\s*[\"\']begin[\"\'][^>]*\\s*/?>.*?<((?:w:)?fldChar)[^>]*fldCharType\\s*=\\s*[\"\']end[\"\'][^>]*\\s*/?>"
        );
        Pattern instr = Pattern.compile(
                "(?is)<(?:w:)?instrText\\b[^>]*>.*?</(?:w:)?instrText\\s*>"
        );

        Matcher regions = fieldRegion.matcher(xml);
        StringBuffer out = new StringBuffer();
        while (regions.find()) {
            String region = regions.group();
            StringBuilder instructionText = new StringBuilder();
            Matcher regionInstr = instr.matcher(region);
            while (regionInstr.find()) {
                instructionText.append(regionInstr.group().replaceAll("(?is)<[^>]+>", ""));
            }
            if (token.matcher(instructionText).find()) {
                region = instr.matcher(region).replaceAll("");
            }
            regions.appendReplacement(out, Matcher.quoteReplacement(region));
        }
        regions.appendTail(out);
        String result = out.toString();

        // fldSimple stores its instruction in an attribute. Remove only the
        // instruction attribute when it contains the dangerous capability.
        Pattern fldSimple = Pattern.compile(
                "(?is)(<(?:w:)?fldSimple\\b[^>]*\\b(?:w:)?instr\\s*=\\s*[\\\"'])([^\\\"']*)([\\\"'])"
        );
        Matcher simple = fldSimple.matcher(result);
        StringBuffer simpleOut = new StringBuffer();
        while (simple.find()) {
            String instruction = simple.group(2);
            if (token.matcher(instruction).find()) {
                simple.appendReplacement(simpleOut,
                        Matcher.quoteReplacement(simple.group(1) + simple.group(3)));
            } else {
                simple.appendReplacement(simpleOut, Matcher.quoteReplacement(simple.group()));
            }
        }
        simple.appendTail(simpleOut);
        result = simpleOut.toString();

        // A malformed/fragmented field may not have a clean begin/end pair.
        // In that case, remove only instrText elements that individually carry
        // the dangerous token; cached result runs remain intact.
        Matcher individual = instr.matcher(result);
        StringBuffer individualOut = new StringBuffer();
        while (individual.find()) {
            String plain = individual.group().replaceAll("(?is)<[^>]+>", " ");
            if (token.matcher(plain).find()) {
                individual.appendReplacement(individualOut, "");
            } else {
                individual.appendReplacement(individualOut, Matcher.quoteReplacement(individual.group()));
            }
        }
        individual.appendTail(individualOut);
        return individualOut.toString();
    }

    /**
     * Removes only Excel formula instructions that reference an external
     * workbook or DDE-style source. The surrounding cell and cached <v>
     * value are deliberately preserved.
     */
    private String removeExcelExternalFormulaElements(String xml) {
        return sanitizeExcelFormulaElements(xml, true, false);
    }

    /**
     * Removes active/dangerous Excel formula instructions while preserving
     * the containing cell and cached result. This also handles definedName
     * formulas in workbook.xml, not just worksheet <f> elements.
     */
    private String removeExcelActiveFormulaElements(String xml) {
        return sanitizeExcelFormulaElements(xml, false, true);
    }

    private String sanitizeExcelFormulaElements(String xml,
                                                boolean externalWorkbook,
                                                boolean active) {
        if (xml == null || xml.isEmpty()) return xml;

        Pattern formulaElement = Pattern.compile(
                "(?is)<(?:[A-Za-z_][\\w.-]*:)?f\\b[^>]*>.*?</(?:[A-Za-z_][\\w.-]*:)?f\\s*>"
        );
        Matcher m = formulaElement.matcher(xml);
        StringBuffer out = new StringBuffer();
        while (m.find()) {
            String element = m.group();
            String formulaText = element.replaceAll("(?is)<[^>]+>", "");
            boolean remove = false;
            if (externalWorkbook) {
                remove = formulaText.matches("(?is).*\\[[^\\]]+\\][^!\\s]+!.*")
                        || formulaText.matches("(?is).*\\bDDE(?:AUTO)?\\b.*");
            }
            if (active) {
                remove = remove || containsDangerousExcelFunction(formulaText)
                        || containsDangerousHyperlink(formulaText)
                        || containsDde(formulaText);
            }
            m.appendReplacement(out, remove ? "" : Matcher.quoteReplacement(element));
        }
        m.appendTail(out);

        // Excel defined names store formulas as element text in workbook.xml.
        // They do not use <f>, so remove only the unsafe defined-name element.
        Pattern definedName = Pattern.compile(
                "(?is)<(?:[A-Za-z_][\\w.-]*:)?definedName\\b[^>]*>.*?</(?:[A-Za-z_][\\w.-]*:)?definedName\\s*>"
        );
        Matcher dn = definedName.matcher(out.toString());
        StringBuffer dnOut = new StringBuffer();
        while (dn.find()) {
            String element = dn.group();
            String formulaText = element.replaceAll("(?is)<[^>]+>", "");
            boolean remove = false;
            if (externalWorkbook) {
                remove = formulaText.matches("(?is).*\\[[^\\]]+\\][^!\\s]+!.*");
            }
            if (active) {
                remove = remove || containsDangerousExcelFunction(formulaText)
                        || containsDangerousHyperlink(formulaText)
                        || containsDde(formulaText);
            }
            dn.appendReplacement(dnOut, remove ? "" : Matcher.quoteReplacement(element));
        }
        dn.appendTail(dnOut);
        return dnOut.toString();
    }

    private boolean containsDangerousExcelFunction(String formula) {
        if (formula == null) return false;
        return Pattern.compile("(?is)(?:^|[^A-Za-z0-9_.])(RTD|CALL|REGISTER\\.ID|EXEC|RUN|GET\\.CELL|GET\\.WORKBOOK)\\s*\\(").matcher(formula).find()
                || Pattern.compile("(?is)(?:^|[^A-Za-z0-9_.])(WEBSERVICE|FILTERXML)\\s*\\(").matcher(formula).find();
    }

    private boolean containsDangerousHyperlink(String formula) {
        if (formula == null) return false;
        return Pattern.compile("(?is)HYPERLINK\\s*\\(\\s*[\\\"']\\s*(?:file:|javascript:|vbscript:|data:|ms-|shell:|mk:|\\\\\\\\|/\\\\)").matcher(formula).find();
    }

    private boolean containsDde(String formula) {
        return formula != null && Pattern.compile("(?i)\\bDDE(?:AUTO)?\\b").matcher(formula).find();
    }
    private String removeDangerousPptxActions(OOXMLPackage pkg,
                                              String sourcePart,
                                              String xml,
                                              List<String> actions) {
        Matcher matcher = DANGEROUS_PPTX_ACTION_ELEMENT.matcher(xml);
        StringBuffer out = new StringBuffer();

        while (matcher.find()) {
            String element = matcher.group();
            Matcher rel = REL_REFERENCE.matcher(element);
            if (rel.find()) {
                String relationshipId = rel.group(1);
                if (pkg.removeRelationship(sourcePart, relationshipId)) {
                    actions.add("Removed PowerPoint active-action relationship " + relationshipId + " from " + sourcePart);
                }
            }
            matcher.appendReplacement(out, "");
        }
        matcher.appendTail(out);

        String result = out.toString();
        result = DANGEROUS_PPTX_ACTION_ATTRIBUTE.matcher(result).replaceAll("");
        return result;
    }

    private String sanitizeXmlDeclarations(String xml) {
        Set<String> declaredEntities = new HashSet<>();
        Matcher declarations = ENTITY_DECL.matcher(xml);
        while (declarations.find()) {
            declaredEntities.add(declarations.group(1));
        }

        String result = removeDoctype(xml);
        result = ENTITY_DECL.matcher(result).replaceAll("");

        // Do not remove the five predefined XML entities. Remove references
        // to custom entities declared by the unsafe DTD so they cannot remain
        // unresolved after the DTD is stripped.
        if (!declaredEntities.isEmpty()) {
            Matcher refs = CUSTOM_ENTITY_REF.matcher(result);
            StringBuffer out = new StringBuffer();
            while (refs.find()) {
                String entity = refs.group(1);
                if (declaredEntities.contains(entity)) {
                    refs.appendReplacement(out, "");
                } else {
                    refs.appendReplacement(out, Matcher.quoteReplacement(refs.group()));
                }
            }
            refs.appendTail(out);
            result = out.toString();
        }

        return result;
    }

    private String removeDoctype(String xml) {
        int start = indexOfIgnoreCase(xml, "<!DOCTYPE");
        while (start >= 0) {
            int i = start + "<!DOCTYPE".length();
            int subsetDepth = 0;
            char quote = 0;
            int end = -1;

            for (; i < xml.length(); i++) {
                char c = xml.charAt(i);
                if (quote != 0) {
                    if (c == quote) quote = 0;
                    continue;
                }
                if (c == '\'' || c == '"') {
                    quote = c;
                } else if (c == '[') {
                    subsetDepth++;
                } else if (c == ']' && subsetDepth > 0) {
                    subsetDepth--;
                } else if (c == '>' && subsetDepth == 0) {
                    end = i;
                    break;
                }
            }

            if (end < 0) return xml.substring(0, start);
            xml = xml.substring(0, start) + xml.substring(end + 1);
            start = indexOfIgnoreCase(xml, "<!DOCTYPE");
        }
        return xml;
    }

    private int indexOfIgnoreCase(String value, String token) {
        return value.toLowerCase(Locale.ROOT).indexOf(token.toLowerCase(Locale.ROOT));
    }

    private void removeRelationship(OOXMLPackage pkg,
                                    SecurityFinding finding,
                                    List<String> actions) {
        String source = finding.getSourcePart();
        String id = finding.getRelationshipId();
        if (id == null) return;

        if (pkg.removeRelationship(source, id)) {
            removeRelationshipReferences(pkg, source, id, actions);
            actions.add("Removed relationship " + id + " from " + source);
        }
    }

    private void removeUnsafePart(OOXMLPackage pkg,
                                  String partName,
                                  List<String> actions,
                                  Set<String> removedParts) {
        if (partName == null || partName.isBlank() || !removedParts.add(partName)) return;

        List<OOXMLRelationship> incoming = new ArrayList<>();
        for (OOXMLRelationship relationship : pkg.getRelationships()) {
            if (relationship == null || relationship.isExternal() || relationship.getTarget() == null) continue;

            String resolved = resolveTarget(
                    relationship.getSourcePart(),
                    relationship.getTarget()
            );

            if (partName.equals(resolved)) {
                incoming.add(relationship);
            }
        }

        for (OOXMLRelationship relationship : incoming) {
            if (pkg.removeRelationship(relationship.getSourcePart(), relationship.getId())) {
                removeRelationshipReferences(
                        pkg,
                        relationship.getSourcePart(),
                        relationship.getId(),
                        actions
                );
            }
        }

        if (!incoming.isEmpty()) {
            actions.add("Removed " + incoming.size() + " relationship(s) targeting " + partName);
        }

        pkg.removeRelationshipsFrom(partName);

        if (pkg.removePart(partName) != null) {
            actions.add("Removed unsafe package part: " + partName);
        }
    }

    private String resolveTarget(String sourcePart, String target) {
        if (target == null || target.isBlank()) return null;

        String t = target.trim().replace('\\', '/');
        if (t.startsWith("/") || sourcePart == null || sourcePart.isBlank()) {
            return normalizePath(t);
        }

        String s = sourcePart.replace('\\', '/');
        int slash = s.lastIndexOf('/');
        String dir = slash < 0 ? "" : s.substring(0, slash);
        return normalizePath(dir.isEmpty() ? t : dir + "/" + t);
    }

    private String normalizePath(String path) {
        String[] pieces = path.split("/");
        List<String> out = new ArrayList<>();
        for (String piece : pieces) {
            if (piece.isEmpty() || ".".equals(piece)) continue;
            if ("..".equals(piece)) {
                if (!out.isEmpty()) out.remove(out.size() - 1);
                continue;
            }
            out.add(piece);
        }
        return String.join("/", out);
    }

    private boolean isDedicatedExternalPart(String partName) {
        String n = partName == null ? "" : partName.toLowerCase(Locale.ROOT);
        return n.equals("xl/connections.xml") || n.startsWith("xl/externallinks/") ||
                n.startsWith("xl/querytables/") || n.startsWith("xl/querytables/") ||
                n.endsWith("/externalconnections.xml");
    }

    private void cleanupOrphanedContentTypes(OOXMLPackage pkg,
                                             Set<String> removedParts,
                                             List<String> actions) {
        for (String partName : removedParts) {
            if (partName == null) continue;
            String normalized = partName.startsWith("/")
                    ? partName.substring(1)
                    : partName;
            if (pkg.removeContentType(normalized)) {
                actions.add("Removed content-type declaration: " + normalized);
            }
        }
    }
}
