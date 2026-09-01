package model.common;

import java.util.ArrayList;
import java.util.List;

public class TextComponent {

    // =========================================================
    // BASIC TEXT INFORMATION
    // =========================================================

    private String id;
    private String text;

    private String fontName;
    private double fontSize;

    private boolean bold;
    private boolean italic;
    private boolean underline;

    private String alignment;

    // =========================================================
    // POSITION
    // =========================================================

    private int pageNumber;

    private double x;
    private double y;
    private double width;
    private double height;

    // =========================================================
    // RICH TEXT
    // =========================================================

    private List<TextParagraphComponent> paragraphs =
            new ArrayList<>();

    // =========================================================
    // CONSTRUCTORS
    // =========================================================

    public TextComponent() {
    }

    public TextComponent(String text) {
        this.text = text;
    }

    // =========================================================
    // BASIC TEXT
    // =========================================================

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    // =========================================================
    // FONT
    // =========================================================

    public String getFontName() {
        return fontName;
    }

    public void setFontName(String fontName) {
        this.fontName = fontName;
    }

    public double getFontSize() {
        return fontSize;
    }

    public void setFontSize(double fontSize) {
        this.fontSize = fontSize;
    }

    // =========================================================
    // STYLE
    // =========================================================

    public boolean isBold() {
        return bold;
    }

    public void setBold(boolean bold) {
        this.bold = bold;
    }

    public boolean isItalic() {
        return italic;
    }

    public void setItalic(boolean italic) {
        this.italic = italic;
    }

    public boolean isUnderline() {
        return underline;
    }

    public void setUnderline(boolean underline) {
        this.underline = underline;
    }

    // =========================================================
    // ALIGNMENT
    // =========================================================

    public String getAlignment() {
        return alignment;
    }

    public void setAlignment(String alignment) {
        this.alignment = alignment;
    }

    // =========================================================
    // POSITION
    // =========================================================

    public int getPageNumber() {
        return pageNumber;
    }

    public void setPageNumber(int pageNumber) {
        this.pageNumber = pageNumber;
    }

    public double getX() {
        return x;
    }

    public void setX(double x) {
        this.x = x;
    }

    public double getY() {
        return y;
    }

    public void setY(double y) {
        this.y = y;
    }

    public double getWidth() {
        return width;
    }

    public void setWidth(double width) {
        this.width = width;
    }

    public double getHeight() {
        return height;
    }

    public void setHeight(double height) {
        this.height = height;
    }

    // =========================================================
    // RICH TEXT
    // =========================================================

    public List<TextParagraphComponent> getParagraphs() {
        return paragraphs;
    }

    public void setParagraphs(
            List<TextParagraphComponent> paragraphs) {

        this.paragraphs =
                paragraphs != null
                        ? paragraphs
                        : new ArrayList<>();
    }

    public void addParagraph(
            TextParagraphComponent paragraph) {

        if (paragraph != null) {
            paragraphs.add(paragraph);
        }
    }

    // =========================================================
    // PARAGRAPH
    // =========================================================

    public static class TextParagraphComponent {

        private String text = "";

        private String alignment;

        private double leftMargin;
        private double rightMargin;
        private double indent;

        private List<TextRunComponent> runs =
                new ArrayList<>();

        // -----------------------------------------------------
        // TEXT
        // -----------------------------------------------------

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text != null ? text : "";
        }

        // -----------------------------------------------------
        // ALIGNMENT
        // -----------------------------------------------------

        public String getAlignment() {
            return alignment;
        }

        public void setAlignment(String alignment) {
            this.alignment = alignment;
        }

        // -----------------------------------------------------
        // MARGINS
        // -----------------------------------------------------

        public double getLeftMargin() {
            return leftMargin;
        }

        public void setLeftMargin(double leftMargin) {
            this.leftMargin = leftMargin;
        }

        public double getRightMargin() {
            return rightMargin;
        }

        public void setRightMargin(double rightMargin) {
            this.rightMargin = rightMargin;
        }

        public double getIndent() {
            return indent;
        }

        public void setIndent(double indent) {
            this.indent = indent;
        }

        // -----------------------------------------------------
        // RUNS
        // -----------------------------------------------------

        public List<TextRunComponent> getRuns() {
            return runs;
        }

        public void setRuns(
                List<TextRunComponent> runs) {

            this.runs =
                    runs != null
                            ? runs
                            : new ArrayList<>();
        }

        public void addRun(
                TextRunComponent run) {

            if (run != null) {
                runs.add(run);

                if (run.getText() != null) {
                    text += run.getText();
                }
            }
        }
    }

    // =========================================================
    // TEXT RUN
    // =========================================================

    public static class TextRunComponent {

        private String text;

        private String fontName;
        private double fontSize;

        private Boolean bold;
        private Boolean italic;
        private Boolean underline;

        private String fontColor;

        // -----------------------------------------------------
        // TEXT
        // -----------------------------------------------------

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }

        // -----------------------------------------------------
        // FONT
        // -----------------------------------------------------

        public String getFontName() {
            return fontName;
        }

        public void setFontName(String fontName) {
            this.fontName = fontName;
        }

        public double getFontSize() {
            return fontSize;
        }

        public void setFontSize(double fontSize) {
            this.fontSize = fontSize;
        }

        // -----------------------------------------------------
        // BOLD
        // -----------------------------------------------------

        public Boolean getBold() {
            return bold;
        }

        public void setBold(Boolean bold) {
            this.bold = bold;
        }

        public boolean isBold() {
            return Boolean.TRUE.equals(bold);
        }

        // -----------------------------------------------------
        // ITALIC
        // -----------------------------------------------------

        public Boolean getItalic() {
            return italic;
        }

        public void setItalic(Boolean italic) {
            this.italic = italic;
        }

        public boolean isItalic() {
            return Boolean.TRUE.equals(italic);
        }

        // -----------------------------------------------------
        // UNDERLINE
        // -----------------------------------------------------

        public Boolean getUnderline() {
            return underline;
        }

        public void setUnderline(Boolean underline) {
            this.underline = underline;
        }

        public boolean isUnderline() {
            return Boolean.TRUE.equals(underline);
        }

        // -----------------------------------------------------
        // FONT COLOR
        // -----------------------------------------------------

        public String getFontColor() {
            return fontColor;
        }

        public void setFontColor(String fontColor) {
            this.fontColor = fontColor;
        }

        // -----------------------------------------------------
        // COLOR ALIAS
        // -----------------------------------------------------

        public String getColor() {
            return fontColor;
        }

        public void setColor(String color) {
            this.fontColor = color;
        }
    }

    // =========================================================
    // COMPATIBILITY ALIASES
    // =========================================================
    //
    // PPTXParser currently refers to:
    //
    //     TextComponent.TextParagraph
    //     TextComponent.TextRun
    //
    // Keep these aliases so that the existing parser compiles
    // without forcing another structural change right now.
    // =========================================================

    public static class TextParagraph
            extends TextParagraphComponent {

        public TextParagraph() {
            super();
        }
    }

    public static class TextRun
            extends TextRunComponent {

        public TextRun() {
            super();
        }
    }
}