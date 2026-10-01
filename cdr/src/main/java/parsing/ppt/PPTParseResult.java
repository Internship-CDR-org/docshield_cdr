package parsing.ppt;

import parsing.common.DocumentParser;

public class PPTParseResult {

    private boolean parseSucceeded;
    private boolean extractionValid;

    private int textCount;
    private int imageCount;
    private int embeddedObjectCount;
    private int slideCount;

    private String failureReason;
    private String parserUsed;


    public boolean isParseSucceeded() {
        return parseSucceeded;
    }

    public void setParseSucceeded(
            boolean parseSucceeded) {

        this.parseSucceeded =
                parseSucceeded;
    }


    public boolean isExtractionValid() {
        return extractionValid;
    }

    public void setExtractionValid(
            boolean extractionValid) {

        this.extractionValid =
                extractionValid;
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

    public void setEmbeddedObjectCount(
            int embeddedObjectCount) {

        this.embeddedObjectCount =
                embeddedObjectCount;
    }


    public int getSlideCount() {
        return slideCount;
    }

    public void setSlideCount(int slideCount) {
        this.slideCount = slideCount;
    }


    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(
            String failureReason) {

        this.failureReason =
                failureReason;
    }


    public String getParserUsed() {
        return parserUsed;
    }

    public void setParserUsed(
            String parserUsed) {

        this.parserUsed =
                parserUsed;
    }
}