package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.HyperlinkComponent;
import model.common.ThreatComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFileAttachment;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFInteractiveParser {

    // =============================================================
    // LEGACY INTERACTIVE PARSER
    // =============================================================

    public List<String> parse(Path file)
            throws IOException {

        List<String> findings =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageNumber = 1;

            for (PDPage page :
                    document.getPages()) {

                List<PDAnnotation> annotations =
                        page.getAnnotations();

                for (PDAnnotation annotation :
                        annotations) {

                    findings.add(
                            "Page "
                                    + pageNumber
                                    + " : Annotation = "
                                    + annotation.getSubtype()
                    );

                    // -------------------------------------------------
                    // LINK ANNOTATION
                    // -------------------------------------------------

                    if (annotation
                            instanceof PDAnnotationLink) {

                        PDAnnotationLink link =
                                (PDAnnotationLink)
                                        annotation;

                        PDAction action =
                                link.getAction();

                        if (action != null) {

                            classifyAction(
                                    action,
                                    pageNumber,
                                    findings
                            );
                        }
                    }

                    // -------------------------------------------------
                    // FILE ATTACHMENT
                    // -------------------------------------------------

                    if (annotation
                            instanceof PDAnnotationFileAttachment) {

                        findings.add(
                                "Page "
                                        + pageNumber
                                        + " : "
                                        + "File attachment annotation detected"
                        );
                    }
                }

                pageNumber++;
            }
        }

        return findings;
    }


    // =============================================================
    // HYPERLINK COMPONENTS
    // =============================================================

    public List<HyperlinkComponent>
    parseHyperlinkComponents(Path file)
            throws IOException {

        List<HyperlinkComponent> hyperlinks =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageNumber = 1;
            int linkNumber = 1;

            for (PDPage page :
                    document.getPages()) {

                for (PDAnnotation annotation :
                        page.getAnnotations()) {

                    if (!(annotation
                            instanceof PDAnnotationLink)) {

                        continue;
                    }

                    PDAnnotationLink link =
                            (PDAnnotationLink)
                                    annotation;

                    PDAction action =
                            link.getAction();

                    // Only URI actions can become
                    // normal hyperlink components.
                    if (!(action instanceof PDActionURI)) {

                        continue;
                    }

                    PDActionURI uriAction =
                            (PDActionURI) action;

                    String uri =
                            uriAction.getURI();

                    if (uri == null ||
                            uri.isBlank()) {

                        continue;
                    }

                    uri = uri.trim();

                    /*
                     * IMPORTANT:
                     *
                     * javascript: is NOT a normal hyperlink.
                     * It must be handled by ThreatComponent.
                     */

                    if (isJavaScriptURI(uri)) {

                        continue;
                    }

                    HyperlinkComponent component =
                            new HyperlinkComponent();

                    component.setId(
                            "pdf_hyperlink_" +
                                    linkNumber
                    );

                    component.setTarget(
                            uri
                    );

                    component.setDisplayText(
                            "Page " +
                                    pageNumber +
                                    " link"
                    );

                    hyperlinks.add(
                            component
                    );

                    linkNumber++;
                }

                pageNumber++;
            }
        }

        return hyperlinks;
    }


    // =============================================================
    // THREAT COMPONENTS
    // =============================================================

    public List<ThreatComponent>
    parseThreatComponents(Path file)
            throws IOException {

        List<ThreatComponent> threats =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageNumber = 1;
            int threatNumber = 1;

            for (PDPage page :
                    document.getPages()) {

                for (PDAnnotation annotation :
                        page.getAnnotations()) {

                    if (!(annotation
                            instanceof PDAnnotationLink)) {

                        continue;
                    }

                    PDAnnotationLink link =
                            (PDAnnotationLink)
                                    annotation;

                    PDAction action =
                            link.getAction();

                    if (action == null) {

                        continue;
                    }

                    ThreatComponent threat =
                            null;


                    // -------------------------------------------------
                    // PDF JAVASCRIPT ACTION
                    // -------------------------------------------------

                    if (action
                            instanceof PDActionJavaScript) {

                        threat =
                                createThreat(
                                        "PDF-JAVASCRIPT",
                                        "High",
                                        "JavaScript action detected on page "
                                                + pageNumber,
                                        "DISARM",
                                        "pdf_interactive_" +
                                                threatNumber
                                );
                    }


                    // -------------------------------------------------
                    // PDF LAUNCH ACTION
                    // -------------------------------------------------

                    else if (action
                            instanceof PDActionLaunch) {

                        threat =
                                createThreat(
                                        "PDF-LAUNCH",
                                        "High",
                                        "Launch action detected on page "
                                                + pageNumber,
                                        "DISARM",
                                        "pdf_interactive_" +
                                                threatNumber
                                );
                    }


                    // -------------------------------------------------
                    // URI ACTION
                    // -------------------------------------------------

                    else if (action
                            instanceof PDActionURI) {

                        PDActionURI uriAction =
                                (PDActionURI) action;

                        String uri =
                                uriAction.getURI();

                        if (uri != null) {

                            uri = uri.trim();

                            /*
                             * A javascript: URI is executable
                             * content and therefore a threat.
                             */

                            if (isJavaScriptURI(uri)) {

                                threat =
                                        createThreat(
                                                "PDF-JAVASCRIPT-URI",
                                                "High",
                                                "JavaScript URI detected on page "
                                                        + pageNumber
                                                        + " : "
                                                        + uri,
                                                "DISARM",
                                                "pdf_interactive_" +
                                                        threatNumber
                                        );
                            }
                        }
                    }


                    // -------------------------------------------------
                    // OTHER PDF ACTION
                    // -------------------------------------------------

                    else {

                        threat =
                                createThreat(
                                        "PDF-ACTION",
                                        "Medium",
                                        "Other PDF action detected on page "
                                                + pageNumber +
                                                " : " +
                                                action.getType(),
                                        "DISARM",
                                        "pdf_interactive_" +
                                                threatNumber
                                );
                    }


                    if (threat != null) {

                        threats.add(
                                threat
                        );

                        threatNumber++;
                    }
                }

                pageNumber++;
            }
        }

        return threats;
    }


    // =============================================================
    // JAVASCRIPT URI DETECTION
    // =============================================================

    private boolean isJavaScriptURI(
            String uri) {

        if (uri == null) {
            return false;
        }

        return uri
                .trim()
                .regionMatches(
                        true,
                        0,
                        "javascript:",
                        0,
                        "javascript:".length()
                );
    }


    // =============================================================
    // THREAT CREATION
    // =============================================================

    private ThreatComponent createThreat(
            String ruleId,
            String severity,
            String description,
            String action,
            String componentId) {

        ThreatComponent threat =
                new ThreatComponent();

        threat.setId(
                "pdf_threat_" +
                        componentId
        );

        threat.setRuleId(
                ruleId
        );

        threat.setCategory(
                "PDF Interactive Content"
        );

        threat.setSeverity(
                severity
        );

        threat.setDescription(
                description
        );

        threat.setAction(
                action
        );

        threat.setComponentId(
                componentId
        );

        return threat;
    }


    // =============================================================
    // LEGACY ACTION CLASSIFICATION
    // =============================================================

    private void classifyAction(
            PDAction action,
            int pageNumber,
            List<String> findings) {

        if (action
                instanceof PDActionJavaScript) {

            findings.add(
                    "Page "
                            + pageNumber
                            + " : JavaScript action detected"
            );

        } else if (action
                instanceof PDActionURI) {

            PDActionURI uriAction =
                    (PDActionURI) action;

            String uri =
                    uriAction.getURI();

            if (isJavaScriptURI(uri)) {

                findings.add(
                        "Page "
                                + pageNumber
                                + " : JavaScript URI = "
                                + uri
                );

            } else {

                findings.add(
                        "Page "
                                + pageNumber
                                + " : URI action = "
                                + uri
                );
            }

        } else if (action
                instanceof PDActionLaunch) {

            findings.add(
                    "Page "
                            + pageNumber
                            + " : Launch action detected"
            );

        } else {

            findings.add(
                    "Page "
                            + pageNumber
                            + " : Other action = "
                            + action.getType()
            );
        }
    }
}