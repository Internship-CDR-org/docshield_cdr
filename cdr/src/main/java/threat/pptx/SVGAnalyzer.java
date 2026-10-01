package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPart;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


/**
 * Inspects SVG resources for security-relevant active-content
 * constructs.
 *
 * This analyzer only detects and reports.
 * It never modifies the SVG or the PPTX package.
 */
public class SVGAnalyzer
        implements SecurityAnalyzer<OOXMLPart> {


    @Override
    public List<SecurityFinding> analyze(
            OOXMLPart part) {

        List<SecurityFinding> findings =
                new ArrayList<>();


        if (part == null) {
            return findings;
        }


        String partName =
                part.getPartName();


        String contentType =
                part.getContentType();


        // =====================================================
        // VERIFY THAT THIS IS AN SVG
        // =====================================================

        if (!isSvg(part)) {
            return findings;
        }


        byte[] data =
                part.getData();


        if (data == null ||
                data.length == 0) {

            return findings;
        }


        String svg =
                new String(
                        data,
                        StandardCharsets.UTF_8
                );


        String normalized =
                svg.toLowerCase();


        // =====================================================
        // SCRIPT ELEMENT
        // =====================================================

        if (contains(normalized, "<script")) {

            findings.add(
                    createFinding(
                            part,
                            ThreatType.SCRIPT_CONTENT,
                            ThreatSeverity.HIGH,
                            "<script",
                            "SVG contains a script element.",
                            "Inspect and neutralize the script content before reconstruction."
                    )
            );
        }


        // =====================================================
        // EVENT HANDLERS
        // =====================================================

        String[] eventHandlers = {

                "onclick=",
                "onload=",
                "onerror=",
                "onmouseover=",
                "onmouseenter=",
                "onmouseleave=",
                "onmousemove=",
                "onmousedown=",
                "onmouseup=",
                "onfocus=",
                "onblur=",
                "onkeydown=",
                "onkeyup=",
                "onkeypress="
        };


        for (String eventHandler :
                eventHandlers) {

            if (contains(
                    normalized,
                    eventHandler)) {

                findings.add(
                        createFinding(
                                part,
                                ThreatType.SCRIPT_CONTENT,
                                ThreatSeverity.HIGH,
                                eventHandler,
                                "SVG contains an event-handler attribute that may execute script.",
                                "Inspect and neutralize the active event handler before reconstruction."
                        )
                );
            }
        }


        // =====================================================
        // JAVASCRIPT URI
        // =====================================================

        if (contains(
                normalized,
                "javascript:")) {

            findings.add(
                    createFinding(
                            part,
                            ThreatType.SCRIPT_CONTENT,
                            ThreatSeverity.HIGH,
                            "javascript:",
                            "SVG contains a JavaScript URI.",
                            "Inspect and neutralize the JavaScript URI before reconstruction."
                    )
            );
        }


        // =====================================================
        // FOREIGN OBJECT
        // =====================================================

        if (contains(
                normalized,
                "<foreignobject")) {

            findings.add(
                    createFinding(
                            part,
                            ThreatType.SUSPICIOUS_SVG,
                            ThreatSeverity.MEDIUM,
                            "<foreignObject",
                            "SVG contains a foreignObject element.",
                            "Inspect the embedded content before reconstruction."
                    )
            );
        }


        // =====================================================
        // EXTERNAL RESOURCE REFERENCES
        // =====================================================

        if (contains(
                normalized,
                "xlink:href=") ||
                contains(
                        normalized,
                        "href=")) {

            findings.add(
                    createFinding(
                            part,
                            ThreatType.EXTERNAL_REFERENCE,
                            ThreatSeverity.LOW,
                            "href=",
                            "SVG contains a resource reference that may point outside the SVG.",
                            "Inspect the referenced resource and apply CDR policy."
                    )
            );
        }


        return findings;
    }


    // =========================================================
    // SVG IDENTIFICATION
    // =========================================================

    private boolean isSvg(
            OOXMLPart part) {

        String contentType =
                part.getContentType();

        String partName =
                part.getPartName();


        if (contentType != null &&
                contentType.equalsIgnoreCase(
                        "image/svg+xml")) {

            return true;
        }


        return partName != null &&
                partName.toLowerCase()
                        .endsWith(".svg");
    }


    // =========================================================
    // SAFE STRING CHECK
    // =========================================================

    private boolean contains(
            String value,
            String search) {

        return value != null &&
                search != null &&
                value.contains(search);
    }


    // =========================================================
    // CREATE FINDING
    // =========================================================

    private SecurityFinding createFinding(
            OOXMLPart part,
            ThreatType type,
            ThreatSeverity severity,
            String evidence,
            String description,
            String action) {

        return new SecurityFinding(
                FindingClassification.SUSPICIOUS,
                type,
                severity,
                part,
                null,
                null,
                evidence,
                description,
                action
        );
    }
}