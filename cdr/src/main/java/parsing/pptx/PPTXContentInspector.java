package parsing.pptx;

import parsing.common.DocumentParser;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;


/**
 * Performs high-level inspection of a PPTX package.
 *
 * IMPORTANT:
 *
 * This class does NOT modify the package.
 * It does NOT remove anything.
 * It does NOT declare anything malicious.
 *
 * Its current responsibility is to classify package parts so
 * that specialized security/content analyzers can be attached
 * later.
 *
 *
 * Architecture:
 *
 *      OOXMLPackage
 *            |
 *            v
 *    PPTXContentInspector
 *            |
 *     +------+------+
 *     |             |
 *     v             v
 *  classification  routing
 *                     |
 *                     v
 *              specialized analyzers
 */
public class PPTXContentInspector {


    // =========================================================
    // PART CATEGORIES
    // =========================================================

    public enum PartCategory {

        PRESENTATION,

        SLIDE,

        SLIDE_LAYOUT,

        SLIDE_MASTER,

        THEME,

        NOTES_SLIDE,

        NOTES_MASTER,

        RELATIONSHIP,

        CONTENT_TYPES,

        MEDIA,

        FONT,

        CHART,

        EMBEDDING,

        ACTIVEX,

        VBA,

        CUSTOM_XML,

        PROPERTIES,

        OTHER_XML,

        OTHER_BINARY,

        UNKNOWN
    }


    // =========================================================
    // INSPECTION RESULT
    // =========================================================

    public static class InspectionResult {

        private final OOXMLPart part;

        private final PartCategory category;


        public InspectionResult(
                OOXMLPart part,
                PartCategory category) {

            this.part = part;
            this.category = category;
        }


        public OOXMLPart getPart() {

            return part;
        }


        public PartCategory getCategory() {

            return category;
        }


        public String getPartName() {

            if (part == null) {
                return null;
            }

            return part.getPartName();
        }


        public String getContentType() {

            if (part == null) {
                return null;
            }

            return part.getContentType();
        }


        @Override
        public String toString() {

            return "InspectionResult{" +
                    "part='" +
                    getPartName() +
                    '\'' +
                    ", category=" +
                    category +
                    ", contentType='" +
                    getContentType() +
                    '\'' +
                    '}';
        }
    }


    // =========================================================
    // PUBLIC INSPECTION API
    // =========================================================

    /**
     * Inspects every physical part in the package.
     *
     * No modifications are made.
     */
    public List<InspectionResult> inspect(
            OOXMLPackage pptxPackage) {

        List<InspectionResult> results =
                new ArrayList<>();


        if (pptxPackage == null) {
            return results;
        }


        for (OOXMLPart part :
                pptxPackage.getParts()) {

            if (part == null) {
                continue;
            }


            PartCategory category =
                    classifyPart(
                            part
                    );


            results.add(
                    new InspectionResult(
                            part,
                            category
                    )
            );
        }


        return results;
    }


    // =========================================================
    // CLASSIFICATION
    // =========================================================

    /**
     * Determines the broad category of a PPTX package part.
     *
     * This is intentionally conservative.
     *
     * We classify based on package path and content type.
     *
     * We do NOT assume that an unknown part is safe.
     */
    public PartCategory classifyPart(
            OOXMLPart part) {

        if (part == null ||
                part.getPartName() == null) {

            return PartCategory.UNKNOWN;
        }


        String name =
                part.getPartName()
                        .replace(
                                '\\',
                                '/'
                        )
                        .toLowerCase(
                                Locale.ROOT
                        );


        String contentType =
                part.getContentType();


        if (contentType == null) {
            contentType = "";
        }


        contentType =
                contentType.toLowerCase(
                        Locale.ROOT
                );


        // =====================================================
        // SPECIAL PACKAGE FILES
        // =====================================================

        if ("[content_types].xml".equals(
                name
        )) {

            return PartCategory.CONTENT_TYPES;
        }


        if (name.equals(
                "_rels/.rels"
        ) ||
                name.endsWith(
                        ".rels"
                )) {

            return PartCategory.RELATIONSHIP;
        }


        // =====================================================
        // PRESENTATION
        // =====================================================

        if (name.equals(
                "ppt/presentation.xml"
        )) {

            return PartCategory.PRESENTATION;
        }


        // =====================================================
        // SLIDES
        // =====================================================

        if (name.startsWith(
                "ppt/slides/slide"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.SLIDE;
        }


        // =====================================================
        // SLIDE LAYOUTS
        // =====================================================

        if (name.startsWith(
                "ppt/slidelayouts/"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.SLIDE_LAYOUT;
        }


        // =====================================================
        // SLIDE MASTERS
        // =====================================================

        if (name.startsWith(
                "ppt/slidemasters/"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.SLIDE_MASTER;
        }


        // =====================================================
        // THEMES
        // =====================================================

        if (name.startsWith(
                "ppt/theme/"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.THEME;
        }


        // =====================================================
        // NOTES SLIDES
        // =====================================================

        if (name.startsWith(
                "ppt/notesslides/"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.NOTES_SLIDE;
        }


        // =====================================================
        // NOTES MASTERS
        // =====================================================

        if (name.startsWith(
                "ppt/notesmasters/"
        ) &&
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.NOTES_MASTER;
        }


        // =====================================================
        // MEDIA
        // =====================================================

        if (name.startsWith(
                "ppt/media/"
        )) {

            return PartCategory.MEDIA;
        }


        // =====================================================
        // FONTS
        // =====================================================

        if (name.startsWith(
                "ppt/fonts/"
        )) {

            return PartCategory.FONT;
        }


        // =====================================================
        // CHARTS
        // =====================================================

        if (name.startsWith(
                "ppt/charts/"
        )) {

            return PartCategory.CHART;
        }


        // =====================================================
        // EMBEDDINGS
        // =====================================================

        if (name.startsWith(
                "ppt/embeddings/"
        )) {

            return PartCategory.EMBEDDING;
        }


        // =====================================================
        // ACTIVEX
        // =====================================================

        if (name.startsWith(
                "ppt/activex/"
        )) {

            return PartCategory.ACTIVEX;
        }


        // =====================================================
        // VBA
        // =====================================================

        if (name.contains(
                "vbaproject"
        ) ||
                name.contains(
                        "vba"
                )) {

            return PartCategory.VBA;
        }


        // =====================================================
        // CUSTOM XML
        // =====================================================

        if (name.startsWith(
                "customxml/"
        ) ||
                name.startsWith(
                        "ppt/customxml/"
                )) {

            return PartCategory.CUSTOM_XML;
        }


        // =====================================================
        // DOCUMENT PROPERTIES
        // =====================================================

        if (name.startsWith(
                "docprops/"
        )) {

            return PartCategory.PROPERTIES;
        }


        // =====================================================
        // XML BY CONTENT TYPE
        // =====================================================

        if (contentType.contains(
                "xml"
        ) ||
                name.endsWith(
                        ".xml"
                )) {

            return PartCategory.OTHER_XML;
        }


        // =====================================================
        // BINARY
        // =====================================================

        if (name.endsWith(
                ".bin"
        ) ||
                contentType.contains(
                        "octet-stream"
                )) {

            return PartCategory.OTHER_BINARY;
        }


        // =====================================================
        // UNKNOWN
        // =====================================================

        return PartCategory.UNKNOWN;
    }
}