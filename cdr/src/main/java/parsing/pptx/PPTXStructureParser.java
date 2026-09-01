package parsing.pptx;

import parsing.common.DocumentParser;

import model.common.StructureComponent;

import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFSlide;
import org.apache.poi.xslf.usermodel.XSLFShape;
import org.apache.poi.xslf.usermodel.XSLFTextBox;
import org.apache.poi.xslf.usermodel.XSLFPictureShape;
import org.apache.poi.xslf.usermodel.XSLFSimpleShape;
import org.apache.poi.xslf.usermodel.XSLFConnectorShape;
import org.apache.poi.xslf.usermodel.XSLFGroupShape;

import org.apache.poi.sl.usermodel.ShapeType;

import java.awt.Color;
import java.awt.geom.Rectangle2D;

import java.io.IOException;
import java.io.InputStream;

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Parses structural information from a PPTX presentation.
 *
 * IMPORTANT DESIGN PRINCIPLE
 * --------------------------
 *
 * This parser is intended for a UNIVERSAL PPTX RECONSTRUCTOR.
 *
 * Therefore:
 *
 * 1. We extract semantic information where it is useful.
 * 2. We preserve important DrawingML XML that we do not yet
 *    interpret semantically.
 * 3. We do NOT create special Java classes for individual
 *    PowerPoint effects such as shadows, glow, reflection, etc.
 *
 * This allows the reconstructor to preserve features that it
 * does not explicitly understand.
 */
public class PPTXStructureParser {


    // =========================================================
    // XML PATTERNS
    // =========================================================

    /*
     * Example:
     *
     * <a:prstGeom prst="roundRect">
     *
     * Captures:
     *
     * roundRect
     */
    private static final Pattern PRESET_GEOMETRY_PATTERN =
            Pattern.compile(
                    "<(?:a:)?prstGeom[^>]*\\bprst\\s*=\\s*[\"']([^\"']+)[\"']",
                    Pattern.CASE_INSENSITIVE
            );


    /*
     * Example:
     *
     * <a:gd name="adj" fmla="val 7875"/>
     *
     * Captures:
     *
     * val 7875
     */
    private static final Pattern GEOMETRY_ADJUSTMENT_PATTERN =
            Pattern.compile(
                    "<(?:a:)?gd[^>]*\\bname\\s*=\\s*[\"']adj[\"'][^>]*\\bfmla\\s*=\\s*[\"']([^\"']+)[\"']",
                    Pattern.CASE_INSENSITIVE
            );


    /*
     * Handles the reverse attribute order:
     *
     * <a:gd fmla="val 7875" name="adj"/>
     */
    private static final Pattern GEOMETRY_ADJUSTMENT_REVERSE_PATTERN =
            Pattern.compile(
                    "<(?:a:)?gd[^>]*\\bfmla\\s*=\\s*[\"']([^\"']+)[\"'][^>]*\\bname\\s*=\\s*[\"']adj[\"']",
                    Pattern.CASE_INSENSITIVE
            );


    /*
     * PowerPoint rotation:
     *
     * <a:xfrm rot="5400000">
     *
     * 60000 = one degree.
     */
    private static final Pattern ROTATION_PATTERN =
            Pattern.compile(
                    "<(?:a:)?xfrm[^>]*\\brot\\s*=\\s*[\"'](-?\\d+)[\"']",
                    Pattern.CASE_INSENSITIVE
            );


    /*
     * Generic DrawingML effect list.
     *
     * Example:
     *
     * <a:effectLst>
     *     <a:outerShdw ...>
     *         ...
     *     </a:outerShdw>
     * </a:effectLst>
     *
     * We deliberately capture the WHOLE XML block.
     *
     * We do NOT inspect whether it is:
     *
     *     outerShadow
     *     glow
     *     reflection
     *     softEdge
     *     etc.
     *
     * This is what makes the IR generic.
     */
    private static final Pattern EFFECT_LIST_PATTERN =
            Pattern.compile(
                    "<(?:a:)?effectLst\\b[^>]*>.*?</(?:a:)?effectLst>",
                    Pattern.CASE_INSENSITIVE |
                    Pattern.DOTALL
            );


    /*
     * Some DrawingML uses an effect DAG instead of an effect
     * list.
     *
     * Preserve that as well.
     */
    private static final Pattern EFFECT_DAG_PATTERN =
            Pattern.compile(
                    "<(?:a:)?effectDag\\b[^>]*>.*?</(?:a:)?effectDag>",
                    Pattern.CASE_INSENSITIVE |
                    Pattern.DOTALL
            );


    // =========================================================
    // MAIN PARSER
    // =========================================================

    public List<StructureComponent> parseStructureComponents(
            Path file)
            throws IOException {

        List<StructureComponent> components =
                new ArrayList<>();


        try (InputStream inputStream =
                     Files.newInputStream(file);

             XMLSlideShow presentation =
                     new XMLSlideShow(inputStream)) {


            // =================================================
            // PRESENTATION
            // =================================================

            StructureComponent presentationComponent =
                    new StructureComponent();


            presentationComponent.setId(
                    "pptx_presentation"
            );


            presentationComponent.setType(
                    "PRESENTATION"
            );


            presentationComponent.setName(
                    file.getFileName().toString()
            );


            presentationComponent.setIndex(0);


            components.add(
                    presentationComponent
            );


            // =================================================
            // SLIDES
            // =================================================

            int slideNumber = 1;


            for (XSLFSlide slide :
                    presentation.getSlides()) {


                StructureComponent slideComponent =
                        new StructureComponent();


                slideComponent.setId(
                        "pptx_slide_" +
                                slideNumber
                );


                slideComponent.setType(
                        "SLIDE"
                );


                String slideTitle =
                        slide.getTitle();


                if (slideTitle != null &&
                        !slideTitle.isBlank()) {

                    slideComponent.setName(
                            slideTitle.trim()
                    );

                } else {

                    slideComponent.setName(
                            "Slide " +
                                    slideNumber
                    );
                }


                slideComponent.setIndex(
                        slideNumber
                );


                slideComponent.setSlideNumber(
                        slideNumber
                );


                components.add(
                        slideComponent
                );


                // =============================================
                // SLIDE SHAPES
                // =============================================

                int shapeIndex = 0;


                for (XSLFShape shape :
                        slide.getShapes()) {


                    StructureComponent shapeComponent =
                            parseShape(
                                    shape,
                                    slideNumber,
                                    shapeIndex
                            );


                    if (shapeComponent != null) {

                        components.add(
                                shapeComponent
                        );
                    }


                    shapeIndex++;
                }


                slideNumber++;
            }
        }


        return components;
    }


    // =========================================================
    // SHAPE PARSER
    // =========================================================

    private StructureComponent parseShape(
            XSLFShape shape,
            int slideNumber,
            int shapeIndex) {


        if (shape == null) {
            return null;
        }


        StructureComponent component =
                new StructureComponent();


        // =====================================================
        // IDENTITY
        // =====================================================

        component.setId(
                "pptx_slide_" +
                        slideNumber +
                        "_shape_" +
                        shapeIndex
        );


        component.setIndex(
                shapeIndex
        );


        component.setSlideNumber(
                slideNumber
        );


        String shapeName =
                shape.getShapeName();


        component.setName(
                shapeName != null &&
                        !shapeName.isBlank()
                        ? shapeName
                        : "Shape " + shapeIndex
        );


        // =====================================================
        // TYPE
        // =====================================================

        component.setType(
                determineShapeType(shape)
        );


        // =====================================================
        // POSITION / SIZE
        // =====================================================

        Rectangle2D anchor =
                shape.getAnchor();


        if (anchor != null) {

            /*
             * Apache POI exposes XSLF coordinates in points.
             *
             * 1 point = 12,700 EMUs.
             */

            component.setX(
                    pointsToEmu(
                            anchor.getX()
                    )
            );


            component.setY(
                    pointsToEmu(
                            anchor.getY()
                    )
            );


            component.setWidth(
                    pointsToEmu(
                            anchor.getWidth()
                    )
            );


            component.setHeight(
                    pointsToEmu(
                            anchor.getHeight()
                    )
            );
        }


        // =====================================================
        // SIMPLE SHAPE INFORMATION
        // =====================================================

        if (shape instanceof XSLFSimpleShape) {

            XSLFSimpleShape simpleShape =
                    (XSLFSimpleShape) shape;


            // -------------------------------------------------
            // FILL / LINE
            // -------------------------------------------------

            extractStyle(
                    simpleShape,
                    component
            );


            // -------------------------------------------------
            // EXACT GEOMETRY
            // -------------------------------------------------

            extractExactGeometry(
                    simpleShape,
                    component
            );


            // -------------------------------------------------
            // GENERIC DRAWINGML
            // -------------------------------------------------

            extractGenericDrawingXml(
                    simpleShape,
                    component
            );
        }


        return component;
    }


    // =========================================================
    // DETERMINE SHAPE TYPE
    // =========================================================

    private String determineShapeType(
            XSLFShape shape) {


        // -----------------------------------------------------
        // PICTURE
        // -----------------------------------------------------

        if (shape instanceof XSLFPictureShape) {

            return "IMAGE";
        }


        // -----------------------------------------------------
        // CONNECTOR
        // -----------------------------------------------------

        if (shape instanceof XSLFConnectorShape) {

            return "CONNECTOR";
        }


        // -----------------------------------------------------
        // GROUP
        // -----------------------------------------------------

        if (shape instanceof XSLFGroupShape) {

            return "GROUP";
        }


        /*
         * IMPORTANT:
         *
         * XSLFTextShape is also the base class for many
         * AutoShapes which contain text.
         *
         * Therefore we only classify an actual XSLFTextBox
         * as TEXT.
         */

        if (shape instanceof XSLFTextBox) {

            return "TEXT";
        }


        // -----------------------------------------------------
        // AUTO SHAPE / SIMPLE SHAPE
        // -----------------------------------------------------

        if (shape instanceof XSLFSimpleShape) {

            try {

                ShapeType shapeType =
                        ((XSLFSimpleShape) shape)
                                .getShapeType();


                if (shapeType != null) {

                    return shapeType.name();
                }

            } catch (Exception ignored) {

                // Fall through.
            }
        }


        return "SHAPE";
    }


    // =========================================================
    // EXACT GEOMETRY
    // =========================================================

    private void extractExactGeometry(
            XSLFSimpleShape shape,
            StructureComponent component) {


        try {

            Object xmlObject =
                    shape.getXmlObject();


            if (xmlObject == null) {
                return;
            }


            String xml =
                    xmlObject.toString();


            if (xml == null ||
                    xml.isBlank()) {

                return;
            }


            // -------------------------------------------------
            // PRESET GEOMETRY
            // -------------------------------------------------

            Matcher presetMatcher =
                    PRESET_GEOMETRY_PATTERN.matcher(
                            xml
                    );


            if (presetMatcher.find()) {

                String preset =
                        presetMatcher.group(1);


                if (preset != null &&
                        !preset.isBlank()) {

                    component.setPresetGeometry(
                            preset.trim()
                    );
                }
            }


            // -------------------------------------------------
            // GEOMETRY ADJUSTMENT
            // -------------------------------------------------

            Matcher adjustmentMatcher =
                    GEOMETRY_ADJUSTMENT_PATTERN.matcher(
                            xml
                    );


            if (adjustmentMatcher.find()) {

                component.setGeometryAdjustment(
                        adjustmentMatcher
                                .group(1)
                                .trim()
                );

            } else {

                Matcher reverseMatcher =
                        GEOMETRY_ADJUSTMENT_REVERSE_PATTERN
                                .matcher(xml);


                if (reverseMatcher.find()) {

                    component.setGeometryAdjustment(
                            reverseMatcher
                                    .group(1)
                                    .trim()
                    );
                }
            }


            // -------------------------------------------------
            // ROTATION
            // -------------------------------------------------

            Matcher rotationMatcher =
                    ROTATION_PATTERN.matcher(
                            xml
                    );


            if (rotationMatcher.find()) {

                try {

                    component.setRotation(
                            Integer.parseInt(
                                    rotationMatcher.group(1)
                            )
                    );

                } catch (NumberFormatException ignored) {

                    // Ignore invalid rotation.
                }
            }


        } catch (Exception ignored) {

            /*
             * XML geometry is an enhancement.
             *
             * If the underlying XML is unusual, normal POI
             * shape geometry remains available.
             */
        }
    }


    // =========================================================
    // GENERIC DRAWINGML EXTRACTION
    // =========================================================

    // =========================================================
    // GENERIC DRAWINGML EXTRACTION
    // =========================================================

    private void extractGenericDrawingXml(
            XSLFSimpleShape shape,
            StructureComponent component) {

        try {
            Object xmlObject = shape.getXmlObject();

            if (xmlObject == null) {
                return;
            }

            String xml = xmlObject.toString();

            if (xml == null || xml.isBlank()) {
                return;
            }

            // -----------------------------------------------------
            // GENERIC EFFECT LIST
            // -----------------------------------------------------
            Matcher effectMatcher =
                    EFFECT_LIST_PATTERN.matcher(xml);

            while (effectMatcher.find()) {
                String effectXml = effectMatcher.group();

                if (effectXml == null || effectXml.isBlank()) {
                    continue;
                }

                effectXml = makeDrawingMLFragmentSelfContained(effectXml);

                component.addDrawingXml(effectXml);
            }

            // -----------------------------------------------------
            // GENERIC EFFECT DAG
            // -----------------------------------------------------
            Matcher dagMatcher =
                    EFFECT_DAG_PATTERN.matcher(xml);

            while (dagMatcher.find()) {
                String dagXml = dagMatcher.group();

                if (dagXml == null || dagXml.isBlank()) {
                    continue;
                }

                dagXml = makeDrawingMLFragmentSelfContained(dagXml);

                component.addDrawingXml(dagXml);
            }

        } catch (Exception ignored) {
            // Generic XML preservation must never prevent normal parsing.
        }
    }

    /**
     * Makes an extracted DrawingML fragment independently parseable.
     *
     * The original fragment can inherit the DrawingML namespace from
     * its parent shape XML. Once extracted as a standalone fragment,
     * that namespace declaration is no longer present. We therefore
     * add the namespace declaration to the fragment root when needed.
     *
     * This is intentionally generic: no particular effect type is
     * inspected or reconstructed here.
     */
    private String makeDrawingMLFragmentSelfContained(
            String fragment) {

        if (fragment == null || fragment.isBlank()) {
            return fragment;
        }

        String result = fragment.trim();

        // Already contains its own DrawingML namespace declaration.
        if (result.contains("xmlns:a=")) {
            return result;
        }

        int openingEnd = result.indexOf('>');

        if (openingEnd < 0) {
            return result;
        }

        String openingTag = result.substring(0, openingEnd);
        String remainder = result.substring(openingEnd);

        // Only add the namespace to an a:-qualified root element.
        if (!openingTag.startsWith("<a:")) {
            return result;
        }

        openingTag +=
                " xmlns:a=\"http://schemas.openxmlformats.org/" +
                "drawingml/2006/main\"";

        return openingTag + remainder;
    }

    // =========================================================
    // EXTRACT FILL / LINE STYLE
    // =========================================================

    private void extractStyle(
            XSLFSimpleShape shape,
            StructureComponent component) {


        // -----------------------------------------------------
        // FILL
        // -----------------------------------------------------

        try {

            Color fillColor =
                    shape.getFillColor();


            if (fillColor != null) {

                component.setFillColor(
                        colorToHex(fillColor)
                );


                component.setFillAlpha(
                        alphaToIrValue(
                                fillColor.getAlpha()
                        )
                );
            }

        } catch (Exception ignored) {

            /*
             * Some PowerPoint shapes intentionally have
             * no fill.
             */
        }


        // -----------------------------------------------------
        // LINE COLOR
        // -----------------------------------------------------

        try {

            Color lineColor =
                    shape.getLineColor();


            if (lineColor != null) {

                component.setLineColor(
                        colorToHex(lineColor)
                );


                component.setLineAlpha(
                        alphaToIrValue(
                                lineColor.getAlpha()
                        )
                );
            }

        } catch (Exception ignored) {

            /*
             * Some shapes intentionally have no line.
             */
        }


        // -----------------------------------------------------
        // LINE WIDTH
        // -----------------------------------------------------

        try {

            double lineWidth =
                    shape.getLineWidth();


            if (lineWidth > 0) {

                /*
                 * Preserve the actual value.
                 *
                 * Do not round it.
                 */

                component.setLineWidth(
                        lineWidth
                );
            }

        } catch (Exception ignored) {

            // No line width available.
        }
    }


    // =========================================================
    // POINTS → EMU
    // =========================================================

    private long pointsToEmu(
            double points) {


        return Math.round(
                points * 12700.0
        );
    }


    // =========================================================
    // COLOR → HEX
    // =========================================================

    private String colorToHex(
            Color color) {


        if (color == null) {
            return null;
        }


        return String.format(
                "%02X%02X%02X",
                color.getRed(),
                color.getGreen(),
                color.getBlue()
        );
    }


    // =========================================================
    // JAVA ALPHA → IR ALPHA
    // =========================================================

    private int alphaToIrValue(
            int alpha) {


        int clamped =
                Math.max(
                        0,
                        Math.min(
                                255,
                                alpha
                        )
                );


        return (int) Math.round(
                clamped *
                        100000.0 /
                        255.0
        );
    }
}