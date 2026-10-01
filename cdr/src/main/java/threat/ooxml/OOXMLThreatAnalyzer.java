package threat.ooxml;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;
import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;
import threat.common.ThreatAnalyzer;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Common structural security analyzer for OPC/OOXML packages.
 *
 * The analyzer is deliberately capability based. It does not attempt to
 * reproduce antivirus vendor labels; it identifies document capabilities
 * that can execute code, invoke applications, fetch external resources,
 * carry active embedded content, or abuse the package/XML structure.
 */
public final class OOXMLThreatAnalyzer
        implements SecurityAnalyzer<OOXMLPackage>, ThreatAnalyzer<OOXMLPackage> {

    private static final Pattern DOCTYPE =
            Pattern.compile("<!\\s*DOCTYPE\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENTITY_DECL =
            Pattern.compile("<!\\s*ENTITY\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern DDE =
            Pattern.compile("(?i)\\bDDE(?:AUTO)?\\b");
    private static final Pattern WORD_EXTERNAL_FIELD = Pattern.compile(
            "(?is)<(?:[A-Za-z_][\\w.-]*:)?instrText\\b[^>]*>.*?\\b(?:INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\\b.*?</(?:[A-Za-z_][\\w.-]*:)?instrText\\s*>|" +
            "<(?:[A-Za-z_][\\w.-]*:)?fldSimple\\b[^>]*\\b(?:INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT)\\b[^>]*>"
    );

    /* PowerPoint action URIs documented by Microsoft: program, macro and OLE. */
    private static final Pattern PPTX_DANGEROUS_ACTION = Pattern.compile(
            "(?i)ppaction://(?:program|macro(?:\\?[^\\\"'\\s>]*)?|ole(?:\\?[^\\\"'\\s>]*)?)"
    );

    private static final Pattern PPTX_DANGEROUS_ACTION_ATTRIBUTE = Pattern.compile(
            "(?i)\\b(?:action|actionType)\\s*=\\s*\\\"[^\\\"]*(?:runprogram|runmacro|oleverb|ppaction://(?:program|macro|ole|hlinkfile|hlinkpres))[^\\\"]*\\\""
    );

    private static final Pattern RELATIONSHIP_REFERENCE = Pattern.compile(
            "(?i)\\b(?:r:id|r:embed|r:link)\\s*=\\s*[\"']([^\"']+)[\"']"
    );

    /* SVG active/external constructs. */
    private static final Pattern SVG_ACTIVE = Pattern.compile(
            "(?i)<\\s*script\\b|\\bon[a-z][a-z0-9_-]*\\s*=|javascript\\s*:|vbscript\\s*:|<\\s*foreignObject\\b"
    );
    private static final Pattern SVG_EXTERNAL_REFERENCE = Pattern.compile(
            "(?i)(?:href|xlink:href|src)\\s*=\\s*['\\\"]\\s*(?:https?:|file:|javascript:|vbscript:|data:)",
            Pattern.CASE_INSENSITIVE
    );

    private static final String PPT_REL_NS =
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";

    @Override
    public List<SecurityFinding> analyze(OOXMLPackage packageData) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (packageData == null) return findings;

        analyzeParts(packageData, findings);
        analyzeRelationships(packageData, findings);
        return findings;
    }

    private void analyzeParts(OOXMLPackage pkg, List<SecurityFinding> findings) {
        for (OOXMLPart part : pkg.getParts()) {
            if (part == null || part.getPartName() == null) continue;

            String name = part.getPartName().toLowerCase(Locale.ROOT);
            String ct = lower(part.getContentType());
            byte[] data = part.getData();

            // -------------------------------------------------
            // Office macro projects / macro companion data
            // -------------------------------------------------
            if (name.endsWith("/vbaproject.bin") ||
                    name.endsWith("/vbaprojectsignature.bin") ||
                    name.endsWith("/vbadata.xml")) {
                add(findings, FindingClassification.THREAT, ThreatType.VBA_PROJECT,
                        ThreatSeverity.HIGH, part, null, null,
                        "VBA project-related part: " + name,
                        "The package contains an Office VBA project or companion part.",
                        "Remove the VBA project and all package references to it.");
            }

            // -------------------------------------------------
            // ActiveX and PowerPoint control persistence
            // -------------------------------------------------
            if (name.contains("/activex/") ||
                    name.contains("/ctrlprops/") ||
                    ct.contains("activex") ||
                    ct.contains("control")) {
                add(findings, FindingClassification.THREAT, ThreatType.ACTIVEX_OBJECT,
                        ThreatSeverity.HIGH, part, null, null,
                        "ActiveX/control part: " + name,
                        "The package contains an ActiveX control or its control-persistence data.",
                        "Remove the control and its associated package relationships.");
            }

            // -------------------------------------------------
            // Excel-only active content (kept here because the
            // analyzer is shared across OOXML formats)
            // -------------------------------------------------
            if (name.startsWith("xl/macrosheets/") || ct.contains("macrosheet")) {
                add(findings, FindingClassification.THREAT, ThreatType.XLM_MACRO,
                        ThreatSeverity.CRITICAL, part, null, null,
                        "Excel 4.0/XLM macro sheet: " + name,
                        "The workbook contains legacy Excel macro-sheet content.",
                        "Remove the XLM macro sheet and its relationships.");
            }

            if (name.startsWith("xl/externallinks/") ||
                    name.equals("xl/connections.xml") ||
                    name.startsWith("xl/querytables/")) {
                add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, part, null, null,
                        "External data/connection part: " + name,
                        "The workbook contains an external data acquisition structure.",
                        "Remove the external connection/link/query part and its relationships.");
            }

            // -------------------------------------------------
            // Embedded objects/packages
            // -------------------------------------------------
            if (name.contains("/embeddings/") || ct.contains("oleobject")) {
                ThreatType type = ct.contains("oleobject") || name.endsWith(".bin")
                        ? ThreatType.OLE_OBJECT
                        : ThreatType.EMBEDDED_PACKAGE;
                // Presence alone is not a threat. Embedded objects are a
                // security boundary and must be inspected recursively before
                // deciding whether the object itself has to be removed.
                add(findings, FindingClassification.OBSERVATION, type,
                        ThreatSeverity.INFO, part, null, null,
                        "Embedded object/package part: " + name + ", content type: " + ct,
                        "An embedded object/package was discovered and requires deeper content inspection.",
                        "Inspect the embedded content; remove it only when unsafe content is confirmed.");
            }

            // -------------------------------------------------
            // PowerPoint-specific SVG security
            // -------------------------------------------------
            if (isSvg(name, ct)) {
                String text = utf8(data);
                if (SVG_ACTIVE.matcher(text).find() || SVG_EXTERNAL_REFERENCE.matcher(text).find()) {
                    add(findings, FindingClassification.THREAT, ThreatType.SUSPICIOUS_SVG,
                            ThreatSeverity.HIGH, part, null, null,
                            "Active or externally referenced SVG construct detected in " + name,
                            "The SVG contains script/event-handler content or a URI capable of loading/executing external content.",
                            "Remove the unsafe SVG resource and references to it, or replace it with a passive representation.");
                }
            }

            // -------------------------------------------------
            // XML-level active/external constructs
            // -------------------------------------------------
            if ((part.isXml() || name.endsWith(".xml") || name.endsWith(".rels") ||
                    name.equals("[content_types].xml")) && data != null && data.length > 0) {
                String xml = utf8(data);

                if (DOCTYPE.matcher(xml).find() || ENTITY_DECL.matcher(xml).find()) {
                    add(findings, FindingClassification.THREAT, ThreatType.MALICIOUS_XML,
                            ThreatSeverity.HIGH, part, null, null,
                            "DOCTYPE/ENTITY declaration detected in " + name,
                            "External XML entity constructs are not permitted in the untrusted package model.",
                            "Reject the unsafe XML input or reconstruct the affected part from a trusted representation.");
                }

                if (isDde(name, xml)) {
                    add(findings, FindingClassification.THREAT, ThreatType.DDE,
                            ThreatSeverity.CRITICAL, part, null, null,
                            "DDE/DDEAUTO construct detected in " + name,
                            "Dynamic Data Exchange can invoke external applications or retrieve external data.",
                            "Remove the DDE/DDEAUTO construct during sanitization.");
                }

                if (name.startsWith("word/") && WORD_EXTERNAL_FIELD.matcher(xml).find()) {
                    add(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_RESOURCE,
                            ThreatSeverity.HIGH, part, null, null,
                            "Word external field construct detected in " + name,
                            "External field codes can retrieve content outside the package.",
                            "Remove the external field construct during CDR.");
                }

                // PresentationML interactive actions can execute a program,
                // run a macro, or invoke an OLE verb.
                if (name.startsWith("ppt/") &&
                        (PPTX_DANGEROUS_ACTION.matcher(xml).find() ||
                                PPTX_DANGEROUS_ACTION_ATTRIBUTE.matcher(xml).find())) {
                    add(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_ACTION,
                            ThreatSeverity.CRITICAL, part, null, null,
                            "PowerPoint program/macro/OLE action detected in " + name,
                            "The presentation contains an interactive action capable of invoking active content.",
                            "Remove the dangerous action and any relationship it uses.");
                }

                // Every OOXML relationship reference must resolve to a relationship
                // from the same source part. This is a common OPC invariant, not a
                // PowerPoint-only rule: DOCX, XLSX and PPTX can all carry dangling
                // r:id/r:embed/r:link references after malicious or malformed edits.
                if (!name.endsWith(".rels")) {
                    Matcher refs = RELATIONSHIP_REFERENCE.matcher(xml);
                    while (refs.find()) {
                        String relationshipId = refs.group(1);
                        if (relationshipId == null || relationshipId.isBlank()) continue;
                        boolean exists = false;
                        for (OOXMLRelationship relationship : pkg.getRelationshipsFrom(part.getPartName())) {
                            if (relationshipId.equals(relationship.getId())) { exists = true; break; }
                        }
                        if (!exists) {
                            add(findings, FindingClassification.SUSPICIOUS, ThreatType.INVALID_RELATIONSHIP,
                                    ThreatSeverity.HIGH, part, part.getPartName(), relationshipId,
                                    "Dangling OOXML relationship reference: " + relationshipId + " in " + name,
                                    "An r:id/r:embed/r:link reference does not resolve to a relationship from this part.",
                                    "Remove the invalid relationship reference before reconstruction.");
                        }
                    }
                }
            }

            // -------------------------------------------------
            // Native executable signatures / dangerous scripts
            // -------------------------------------------------
            if (isExecutableEmbedded(name, data)) {
                add(findings, FindingClassification.THREAT, ThreatType.EXECUTABLE_PAYLOAD,
                        ThreatSeverity.CRITICAL, part, null, null,
                        "Executable-looking embedded payload: " + name,
                        "A native executable or script payload is embedded in the package.",
                        "Remove the executable payload and all relationships to it.");
            }

            // -------------------------------------------------
            // Package path traversal
            // -------------------------------------------------
            if (containsTraversal(name)) {
                add(findings, FindingClassification.THREAT, ThreatType.PATH_TRAVERSAL,
                        ThreatSeverity.CRITICAL, part, null, null,
                        "Unsafe package part path: " + name,
                        "A package path attempts to escape the package root.",
                        "Reject the unsafe package rather than preserving the traversing part.");
            }
        }
    }

    private void analyzeRelationships(OOXMLPackage pkg, List<SecurityFinding> findings) {
        for (OOXMLRelationship r : pkg.getRelationships()) {
            if (r == null) continue;

            String target = r.getTarget() == null ? "" : r.getTarget().trim();
            String type = lower(r.getType());
            boolean external = r.isExternal() || looksLikeUri(target);

            // Relationship semantics are security-relevant even when the
            // target is internal. This catches renamed/misleading package
            // parts and relationships whose part names do not reveal their
            // purpose.
            if (isVbaRelationship(type)) {
                addRel(findings, FindingClassification.THREAT, ThreatType.VBA_PROJECT,
                        ThreatSeverity.HIGH, r,
                        "VBA project relationship: " + type,
                        "The package relationship identifies an Office VBA project.",
                        "Remove the VBA project relationship and associated project part.");
                continue;
            }
            if (isActiveXRelationship(type)) {
                addRel(findings, FindingClassification.THREAT, ThreatType.ACTIVEX_OBJECT,
                        ThreatSeverity.HIGH, r,
                        "ActiveX relationship: " + type,
                        "The package relationship identifies an ActiveX control or control binary.",
                        "Remove the ActiveX relationship and associated control parts.");
                continue;
            }

            // Validate the package graph before applying external-URI policy.
            // A local relationship to a missing part is structurally unsafe even
            // when its target string does not look like an external URI.
            if (!external) {
                String resolved = resolveTarget(r.getSourcePart(), target);
                if (resolved == null || pkg.getPart(resolved) == null) {
                    addRel(findings, FindingClassification.SUSPICIOUS, ThreatType.MISSING_TARGET,
                            ThreatSeverity.HIGH, r,
                            "OOXML relationship targets a missing local part: " + target,
                            "The package graph contains a local relationship whose target part does not exist.",
                            "Remove the dangling relationship and any XML reference to it before reconstruction.");
                    continue;
                }
            }

            String lowerTarget = target.toLowerCase(Locale.ROOT);

            // Internal relationships do not participate in external URI policy.
            if (!external) continue;

            if (isDangerousUri(lowerTarget)) {
                addRel(findings, FindingClassification.THREAT, ThreatType.DANGEROUS_URI,
                        ThreatSeverity.CRITICAL, r,
                        "Dangerous external URI: " + target,
                        "The relationship targets a file, script, application, or data URI.",
                        "Remove the dangerous relationship.");
            } else if (isPowerPointActiveRelationship(type)) {
                addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_RESOURCE,
                        ThreatSeverity.HIGH, r,
                        "External PowerPoint active-content relationship: " + target,
                        "An external presentation relationship can supply content or an object from outside the package.",
                        "Remove the external active-content relationship.");
            } else if (type.contains("attachedtemplate") || type.endsWith("/template")) {
                addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_TEMPLATE,
                        ThreatSeverity.HIGH, r,
                        "External template relationship: " + target,
                        "An external template can introduce remotely controlled document content.",
                        "Remove the external template relationship.");
            } else if (type.contains("connection") || type.contains("query") || type.contains("externallink")) {
                addRel(findings, FindingClassification.THREAT, ThreatType.EXTERNAL_CONNECTION,
                        ThreatSeverity.HIGH, r,
                        "External data/connection relationship: " + target,
                        "The relationship can retrieve content from outside the package.",
                        "Remove the external data/connection relationship.");
            } else if (!type.contains("hyperlink")) {
                addRel(findings, FindingClassification.POLICY_VIOLATION, ThreatType.EXTERNAL_RESOURCE,
                        ThreatSeverity.MEDIUM, r,
                        "External non-hyperlink relationship: " + target,
                        "The package references a resource outside its container.",
                        "Remove the external resource relationship during CDR.");
            } else {
                // Ordinary web hyperlinks are interactive user content, not
                // automatically fetched package resources, so preserve them
                // unless the target itself uses a dangerous URI scheme.
                addRel(findings, FindingClassification.OBSERVATION, ThreatType.EXTERNAL_HYPERLINK,
                        ThreatSeverity.INFO, r,
                        "External hyperlink: " + target,
                        "A normal external hyperlink is present.",
                        "Preserve unless policy explicitly requires link removal.");
            }
        }
    }

    private String resolveTarget(String sourcePart, String target) {
        if (target == null || target.isBlank()) return null;
        String t = target.trim().replace('\\', '/');
        if (t.startsWith("/")) return normalizePath(t.substring(1));
        String source = sourcePart == null ? "" : sourcePart.replace('\\', '/');
        int slash = source.lastIndexOf('/');
        String base = slash < 0 ? "" : source.substring(0, slash);
        return normalizePath(base.isEmpty() ? t : base + "/" + t);
    }

    private String normalizePath(String value) {
        if (value == null) return null;
        List<String> pieces = new ArrayList<>();
        for (String piece : value.split("/")) {
            if (piece.isEmpty() || ".".equals(piece)) continue;
            if ("..".equals(piece)) {
                if (pieces.isEmpty()) return null;
                pieces.remove(pieces.size() - 1);
            } else {
                pieces.add(piece);
            }
        }
        return String.join("/", pieces);
    }

    private boolean isVbaRelationship(String type) {
        return type != null && (type.endsWith("/vbaproject") || type.contains("/vbaproject"));
    }

    private boolean isActiveXRelationship(String type) {
        return type != null && (type.contains("/activexcontrol") ||
                type.endsWith("/control") || type.contains("/controlbinary"));
    }

    private boolean isPowerPointActiveRelationship(String type) {
        if (type == null || type.isBlank()) return false;
        return type.contains(PPT_REL_NS.toLowerCase(Locale.ROOT) + "oleobject") ||
                type.endsWith("/oleobject") ||
                type.endsWith("/control") ||
                type.endsWith("/embeddedpackage") ||
                type.endsWith("/package") ||
                type.endsWith("/slide") ||
                type.endsWith("/slidemaster") ||
                type.endsWith("/slidelayout") ||
                type.endsWith("/noteslide") ||
                type.endsWith("/chart") ||
                type.endsWith("/diagramdata") ||
                type.endsWith("/model3d") ||
                type.endsWith("/media");
    }

    private boolean isSvg(String name, String contentType) {
        return name.endsWith(".svg") || "image/svg+xml".equals(contentType);
    }

    private boolean isDde(String name, String xml) {
        if (name.startsWith("word/")) {
            String lower = xml.toLowerCase(Locale.ROOT);
            return (lower.contains("instrtext") || lower.contains("fldsimple")) && DDE.matcher(xml).find();
        }
        if (name.startsWith("xl/")) {
            String lower = lower(xml);
            if (lower.contains("<f") && DDE.matcher(xml).find()) return true;
            return lower.matches("(?s).*<f[^>]*>[^<]*\\|[^<]*!.*</f>.*");
        }
        return false;
    }

    private boolean isExecutableEmbedded(String name, byte[] data) {
        if (data == null || data.length < 2) return false;

        // Do not rely on a filename or /embeddings/ path. A native payload can
        // be hidden in a misleadingly named package part.
        String lowerName = name == null ? "" : name.toLowerCase(Locale.ROOT);
        if (lowerName.endsWith(".exe") || lowerName.endsWith(".dll") ||
                lowerName.endsWith(".com") || lowerName.endsWith(".scr") ||
                lowerName.endsWith(".bat") || lowerName.endsWith(".cmd") ||
                lowerName.endsWith(".ps1") || lowerName.endsWith(".vbs") ||
                lowerName.endsWith(".vbe") || lowerName.endsWith(".js") ||
                lowerName.endsWith(".jse") || lowerName.endsWith(".wsf") ||
                lowerName.endsWith(".wsc") || lowerName.endsWith(".hta")) return true;

        // PE: require MZ plus a valid PE\0\0 signature at e_lfanew. This
        // avoids treating arbitrary text beginning with the letters "MZ" as
        // an executable.
        if (data.length >= 64 && data[0] == 'M' && data[1] == 'Z') {
            long peOffset = ((long)(data[0x3c] & 0xff)) |
                    ((long)(data[0x3d] & 0xff) << 8) |
                    ((long)(data[0x3e] & 0xff) << 16) |
                    ((long)(data[0x3f] & 0xff) << 24);
            if (peOffset >= 0 && peOffset <= data.length - 4 &&
                    data[(int)peOffset] == 'P' && data[(int)peOffset + 1] == 'E' &&
                    data[(int)peOffset + 2] == 0 && data[(int)peOffset + 3] == 0) return true;
        }

        boolean elf = data.length >= 4 && data[0] == 0x7f && data[1] == 'E' &&
                data[2] == 'L' && data[3] == 'F';
        boolean macho32 = data.length >= 4 &&
                ((data[0] == (byte)0xFE && data[1] == (byte)0xED && data[2] == (byte)0xFA && data[3] == (byte)0xCE) ||
                 (data[0] == (byte)0xCE && data[1] == (byte)0xFA && data[2] == (byte)0xED && data[3] == (byte)0xFE));
        boolean macho64 = data.length >= 4 &&
                ((data[0] == (byte)0xFE && data[1] == (byte)0xED && data[2] == (byte)0xFA && data[3] == (byte)0xCF) ||
                 (data[0] == (byte)0xCF && data[1] == (byte)0xFA && data[2] == (byte)0xED && data[3] == (byte)0xFE));
        boolean shebang = data.length >= 2 && data[0] == '#' && data[1] == '!';
        return elf || macho32 || macho64 || shebang;
    }

    private boolean containsTraversal(String name) {
        String n = name.replace('\\', '/');
        if (n.startsWith("/")) return true;
        for (String p : n.split("/")) if ("..".equals(p)) return true;
        return false;
    }

    private boolean isDangerousUri(String target) {
        return target.startsWith("file:") || target.startsWith("javascript:") ||
                target.startsWith("vbscript:") || target.startsWith("data:") ||
                target.startsWith("ms-") || target.startsWith("shell:") ||
                target.startsWith("mk:") || target.startsWith("ms-appx:") ||
                target.startsWith("ms-appdata:") ||
                (target.startsWith("about:") && target.contains("javascript"));
    }

    private boolean looksLikeUri(String value) {
        try {
            return !value.isBlank() && URI.create(value).isAbsolute();
        } catch (Exception ignored) {
            return false;
        }
    }

    private String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private String utf8(byte[] data) {
        return data == null ? "" : new String(data, StandardCharsets.UTF_8);
    }

    private void add(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                     ThreatSeverity s, OOXMLPart part, String source, String rel,
                     String evidence, String description, String action) {
        out.add(new SecurityFinding(c, t, s, part, source, rel, evidence, description, action));
    }

    private void addRel(List<SecurityFinding> out, FindingClassification c, ThreatType t,
                        ThreatSeverity s, OOXMLRelationship r, String evidence,
                        String description, String action) {
        out.add(new SecurityFinding(c, t, s, null, r.getSourcePart(), r.getId(),
                evidence, description, action));
    }
}
