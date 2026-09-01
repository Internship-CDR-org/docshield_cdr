package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.TextComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFContentParser {

    // =============================================================
    // LEGACY TEXT PARSER
    // =============================================================

    public List<String> parseText(Path file)
            throws IOException {

        List<String> text =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            PDFTextStripper stripper =
                    new PDFTextStripper();

            String extracted =
                    stripper.getText(document);

            if (extracted != null
                    && !extracted.isBlank()) {

                text.add(
                        extracted.trim()
                );
            }
        }

        return text;
    }


    // =============================================================
    // COMMON IR TEXT PARSER
    // =============================================================

    public List<TextComponent>
    parseTextComponents(Path file)
            throws IOException {

        List<TextComponent> components =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageNumber = 1;
            int componentNumber = 1;

            for (var page :
                    document.getPages()) {

                LineTextStripper stripper =
                        new LineTextStripper();

                stripper.setStartPage(pageNumber);
                stripper.setEndPage(pageNumber);

                stripper.getText(document);

                for (LineData line :
                        stripper.getLines()) {

                    if (line.text == null
                            || line.text.isBlank()) {

                        continue;
                    }

                    TextComponent component =
                            new TextComponent();

                    component.setId(
                            "pdf_text_" +
                                    componentNumber
                    );

                    component.setText(
                            line.text
                    );

                    component.setPageNumber(
                            pageNumber
                    );

                    component.setX(
                            line.x
                    );

                    component.setY(
                            line.y
                    );

                    component.setWidth(
                            line.width
                    );

                    component.setHeight(
                            line.height
                    );

                    component.setFontName(
                            line.fontName
                    );

                    component.setFontSize(
                            line.fontSize
                    );

                    components.add(
                            component
                    );

                    componentNumber++;
                }

                pageNumber++;
            }
        }

        return components;
    }


    // =============================================================
    // TEXT STRIPPER THAT COLLECTS LINES
    // =============================================================

    private static class LineTextStripper
            extends PDFTextStripper {

        private final List<LineData> lines =
                new ArrayList<>();

        private LineData currentLine;

        private float lineY =
                Float.NaN;

        private float lineX;

        private float lineWidth;

        private float lineHeight;

        private String lineFont;

        private float lineFontSize;


        LineTextStripper()
                throws IOException {

            super();

            setSortByPosition(true);
        }


        List<LineData> getLines() {
            return lines;
        }


        @Override
        protected void writeString(
                String text,
                List<TextPosition> textPositions)
                throws IOException {

            if (text == null
                    || text.isBlank()
                    || textPositions == null
                    || textPositions.isEmpty()) {

                return;
            }


            TextPosition first =
                    textPositions.get(0);

            TextPosition last =
                    textPositions.get(
                            textPositions.size() - 1
                    );


            float x =
                    first.getXDirAdj();

            float y =
                    first.getYDirAdj();

            float width =
                    (last.getXDirAdj()
                            + last.getWidthDirAdj())
                            - x;

            float height =
                    first.getHeightDir();


            /*
             * PDFTextStripper calls writeString()
             * for chunks of text. We combine chunks
             * that belong to approximately the same
             * visual line.
             */

            if (Float.isNaN(lineY)
                    || Math.abs(
                            y - lineY
                    ) > Math.max(
                            2.0f,
                            height * 0.5f
                    )) {

                finishCurrentLine();

                currentLine =
                        new LineData();

                lineY = y;
                lineX = x;
                lineWidth = width;
                lineHeight = height;

                lineFont =
                        first.getFont()
                                .getName();

                lineFontSize =
                        first.getFontSizeInPt();

            } else {

                /*
                 * Extend the current line.
                 */

                lineWidth =
                        Math.max(
                                lineWidth,
                                (x + width) - lineX
                        );

                lineHeight =
                        Math.max(
                                lineHeight,
                                height
                        );
            }


            if (currentLine.text == null) {

                currentLine.text =
                        text;

            } else {

                /*
                 * PDFBox normally provides the
                 * required spacing inside the text
                 * chunks. Add a separator only when
                 * necessary.
                 */

                if (!currentLine.text.endsWith(" ")
                        && !text.startsWith(" ")) {

                    currentLine.text += " ";
                }

                currentLine.text += text;
            }
        }


        @Override
        protected void endPage(
                org.apache.pdfbox.pdmodel.PDPage page)
                throws IOException {

            finishCurrentLine();

            super.endPage(page);
        }


        private void finishCurrentLine() {

            if (currentLine == null
                    || currentLine.text == null
                    || currentLine.text.isBlank()) {

                currentLine = null;
                return;
            }

            currentLine.x =
                    lineX;

            currentLine.y =
                    lineY;

            currentLine.width =
                    lineWidth;

            currentLine.height =
                    lineHeight;

            currentLine.fontName =
                    lineFont;

            currentLine.fontSize =
                    lineFontSize;

            lines.add(
                    currentLine
            );

            currentLine = null;
        }
    }


    // =============================================================
    // INTERNAL LINE DATA
    // =============================================================

    private static class LineData {

        String text;

        float x;
        float y;

        float width;
        float height;

        String fontName;
        float fontSize;
    }
}