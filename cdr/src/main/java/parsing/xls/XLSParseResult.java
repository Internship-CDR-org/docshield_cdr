package parsing.xls;

import parsing.common.DocumentParser;

public class XLSParseResult {

    private boolean parseSucceeded;
    private boolean extractionValid;

    private int sheetCount;
    private int cellCount;
    private int imageCount;
    private int embeddedObjectCount;

    private String failureReason;
    private String parserUsed;


    public boolean isParseSucceeded() {
        return parseSucceeded;
    }

    public void setParseSucceeded(
            boolean parseSucceeded) {

        this.parseSucceeded = parseSucceeded;
    }


    public boolean isExtractionValid() {
        return extractionValid;
    }

    public void setExtractionValid(
            boolean extractionValid) {

        this.extractionValid = extractionValid;
    }


    public int getSheetCount() {
        return sheetCount;
    }

    public void setSheetCount(int sheetCount) {
        this.sheetCount = sheetCount;
    }


    public int getCellCount() {
        return cellCount;
    }

    public void setCellCount(int cellCount) {
        this.cellCount = cellCount;
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


    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(
            String failureReason) {

        this.failureReason = failureReason;
    }


    public String getParserUsed() {
        return parserUsed;
    }

    public void setParserUsed(
            String parserUsed) {

        this.parserUsed = parserUsed;
    }
}