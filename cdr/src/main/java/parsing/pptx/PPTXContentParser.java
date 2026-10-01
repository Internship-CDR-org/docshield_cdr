package parsing.pptx;

import parsing.common.DocumentParser;

import model.common.TextComponent;

import org.apache.poi.sl.usermodel.PaintStyle;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFSlide;
import org.apache.poi.xslf.usermodel.XSLFShape;
import org.apache.poi.xslf.usermodel.XSLFTextShape;
import org.apache.poi.xslf.usermodel.XSLFTextParagraph;
import org.apache.poi.xslf.usermodel.XSLFTextRun;

import java.awt.Color;
import java.awt.geom.Rectangle2D;

import java.io.IOException;
import java.io.InputStream;

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.ArrayList;
import java.util.List;

public class PPTXContentParser {

    // =========================================================
    // COMMON IR TEXT PARSER
    // =========================================================

    public List<TextComponent> parseTextComponents(
            Path file)
            throws IOException {

        List<TextComponent> components =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             XMLSlideShow presentation =
                     new XMLSlideShow(inputStream)) {

            int slideNumber = 1;
            int textNumber = 1;

            for (XSLFSlide slide :
                    presentation.getSlides()) {

                for (XSLFShape shape :
                        slide.getShapes()) {

                    if (!(shape instanceof XSLFTextShape)) {
                        continue;
                    }

                    XSLFTextShape textShape =
                            (XSLFTextShape) shape;

                    String text =
                            textShape.getText();

                    if (text == null ||
                            text.isBlank()) {

                        continue;
                    }

                    Rectangle2D anchor =
                            textShape.getAnchor();

                    TextComponent component =
                            new TextComponent();

                    component.setId(
                            "pptx_text_" +
                                    textNumber
                    );

                    component.setText(
                            text.trim()
                    );

                    component.setPageNumber(
                            slideNumber
                    );

                    if (anchor != null) {

                        component.setX(
                                anchor.getX()
                        );

                        component.setY(
                                anchor.getY()
                        );

                        component.setWidth(
                                anchor.getWidth()
                        );

                        component.setHeight(
                                anchor.getHeight()
                        );
                    }

                    extractRichFormatting(
                            textShape,
                            component
                    );

                    components.add(
                            component
                    );

                    textNumber++;
                }

                slideNumber++;
            }
        }

        return components;
    }


    // =========================================================
    // RICH TEXT EXTRACTION
    // =========================================================

    private void extractRichFormatting(
            XSLFTextShape textShape,
            TextComponent component) {

        List<XSLFTextParagraph> paragraphs =
                textShape.getTextParagraphs();

        if (paragraphs == null ||
                paragraphs.isEmpty()) {

            return;
        }

        for (XSLFTextParagraph sourceParagraph :
                paragraphs) {

            if (sourceParagraph == null) {
                continue;
            }

            TextComponent.TextParagraphComponent
                    paragraph =
                    new TextComponent
                            .TextParagraphComponent();

            if (sourceParagraph.getTextAlign() != null) {

                paragraph.setAlignment(
                        sourceParagraph
                                .getTextAlign()
                                .toString()
                );
            }

            List<XSLFTextRun> sourceRuns =
                    sourceParagraph.getTextRuns();

            StringBuilder paragraphText =
                    new StringBuilder();

            if (sourceRuns != null) {

                for (XSLFTextRun sourceRun :
                        sourceRuns) {

                    if (sourceRun == null) {
                        continue;
                    }

                    String runText =
                            sourceRun.getRawText();

                    if (runText == null) {
                        runText = "";
                    }

                    paragraphText.append(
                            runText
                    );

                    TextComponent.TextRunComponent
                            run =
                            new TextComponent
                                    .TextRunComponent();

                    run.setText(
                            runText
                    );

                    String fontFamily =
                            sourceRun.getFontFamily();

                    if (fontFamily != null &&
                            !fontFamily.isBlank()) {

                        run.setFontName(
                                fontFamily
                        );
                    }

                    Double fontSize =
                            sourceRun.getFontSize();

                    if (fontSize != null &&
                            fontSize > 0) {

                        run.setFontSize(
                                fontSize
                        );
                    }

                    Boolean bold =
                            sourceRun.isBold();

                    if (bold != null) {
                        run.setBold(
                                bold
                        );
                    }

                    Boolean italic =
                            sourceRun.isItalic();

                    if (italic != null) {
                        run.setItalic(
                                italic
                        );
                    }

                    Boolean underline =
                            sourceRun.isUnderlined();

                    if (underline != null) {
                        run.setUnderline(
                                underline
                        );
                    }

                    String fontColor =
                            extractFontColor(
                                    sourceRun
                            );

                    if (fontColor != null) {
                        run.setFontColor(
                                fontColor
                        );
                    }

                    paragraph.addRun(
                            run
                    );
                }
            }

            paragraph.setText(
                    paragraphText.toString()
            );

            component.addParagraph(
                    paragraph
            );
        }

        /*
         * Keep the old flat formatting fields populated from the
         * first available run. This preserves compatibility with
         * older reconstruction/reporting code.
         */
        populateLegacyFormatting(
                component
        );
    }


    // =========================================================
    // LEGACY FORMAT COMPATIBILITY
    // =========================================================

    private void populateLegacyFormatting(
            TextComponent component) {

        List<TextComponent.TextParagraphComponent>
                paragraphs =
                component.getParagraphs();

        if (paragraphs == null ||
                paragraphs.isEmpty()) {

            return;
        }

        TextComponent.TextParagraphComponent
                firstParagraph =
                paragraphs.get(0);

        if (firstParagraph.getAlignment() != null) {

            component.setAlignment(
                    firstParagraph.getAlignment()
            );
        }

        List<TextComponent.TextRunComponent>
                runs =
                firstParagraph.getRuns();

        if (runs == null ||
                runs.isEmpty()) {

            return;
        }

        TextComponent.TextRunComponent firstRun =
                runs.get(0);

        if (firstRun.getFontName() != null) {

            component.setFontName(
                    firstRun.getFontName()
            );
        }

        if (firstRun.getFontSize() > 0) {

            component.setFontSize(
                    firstRun.getFontSize()
            );
        }

        if (firstRun.getBold() != null) {

            component.setBold(
                    firstRun.getBold()
            );
        }

        if (firstRun.getItalic() != null) {

            component.setItalic(
                    firstRun.getItalic()
            );
        }

        if (firstRun.getUnderline() != null) {

            component.setUnderline(
                    firstRun.getUnderline()
            );
        }
    }


    // =========================================================
    // FONT COLOR
    // =========================================================

    private String extractFontColor(
            XSLFTextRun run) {

        try {

            PaintStyle paint =
                    run.getFontColor();

            if (!(paint instanceof PaintStyle.SolidPaint)) {
                return null;
            }

            PaintStyle.SolidPaint solidPaint =
                    (PaintStyle.SolidPaint) paint;

            if (solidPaint.getSolidColor() == null) {
                return null;
            }

            Color color =
                    solidPaint
                            .getSolidColor()
                            .getColor();

            if (color == null) {
                return null;
            }

            return String.format(
                    "%02X%02X%02X",
                    color.getRed(),
                    color.getGreen(),
                    color.getBlue()
            );

        } catch (RuntimeException e) {

            /*
             * Theme colors and inherited colors can sometimes be
             * represented by POI without a directly resolved Color.
             * Do not fail the entire presentation because of that.
             */
            return null;
        }
    }


    // =========================================================
    // LEGACY TEXT PARSER
    // =========================================================

    public List<String> parseText(
            Path file)
            throws IOException {

        List<String> text =
                new ArrayList<>();

        for (TextComponent component :
                parseTextComponents(file)) {

            text.add(
                    component.getText()
            );
        }

        return text;
    }
}