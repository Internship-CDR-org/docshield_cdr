package parsing.doc;

import parsing.common.DocumentParser;

public class DOCParseResult {

    private boolean parseSucceeded;
    private boolean extractionValid;

    private int textCount;
    private int imageCount;
    private int embeddedObjectCount;
    private int paragraphCount;
    
    private String parserUsed;
    private String failureReason;

    public DOCParseResult() {
        this.parseSucceeded = false;
        this.extractionValid = false;
        this.textCount = 0;
        this.imageCount = 0;
        this.embeddedObjectCount = 0;
        paragraphCount = 0;
    }

    public boolean isParseSucceeded() {
        return parseSucceeded;
    }

    public void setParseSucceeded(boolean parseSucceeded) {
        this.parseSucceeded = parseSucceeded;
    }

    public boolean isExtractionValid() {
        return extractionValid;
    }

    public void setExtractionValid(boolean extractionValid) {
        this.extractionValid = extractionValid;
    }

    public int getTextCount() {
        return textCount;
    }

    public void setTextCount(int textCount) {
        this.textCount = textCount;
    }

    public int getImageCount() {
        return imageCount;
    }

    public void setImageCount(int imageCount) {
        this.imageCount = imageCount;
    }

    public int getEmbeddedObjectCount() {
        return embeddedObjectCount;
    }

    public void setEmbeddedObjectCount(int embeddedObjectCount) {
        this.embeddedObjectCount = embeddedObjectCount;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }

    public int getParagraphCount() {
        return paragraphCount;
    }

    public void setParagraphCount(int paragraphCount) {
        this.paragraphCount = paragraphCount;
    }

    public String getParserUsed() {
        return parserUsed;
    }

    public void setParserUsed(String parserUsed) {
        this.parserUsed = parserUsed;
    }
}