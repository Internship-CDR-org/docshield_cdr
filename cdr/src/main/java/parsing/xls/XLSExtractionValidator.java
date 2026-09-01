package parsing.xls;

import parsing.common.DocumentParser;

public class XLSExtractionValidator {

    public boolean validate(XLSParseResult result) {

        if (!result.isParseSucceeded()) {
            return false;
        }

        boolean hasSheets =
                result.getSheetCount() > 0;

        boolean hasCells =
                result.getCellCount() > 0;

        boolean hasImages =
                result.getImageCount() > 0;

        boolean hasObjects =
                result.getEmbeddedObjectCount() > 0;

        /*
         * A valid XLS should contain at least
         * one worksheet and some extractable content.
         */

        if (!hasSheets) {

            result.setExtractionValid(false);

            result.setFailureReason(
                    "HSSF completed but no worksheets were extracted."
            );

            return false;
        }

        if (!hasCells &&
                !hasImages &&
                !hasObjects) {

            result.setExtractionValid(false);

            result.setFailureReason(
                    "HSSF completed but no usable content was extracted."
            );

            return false;
        }

        result.setExtractionValid(true);

        return true;
    }
}