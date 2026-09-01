package parsing.ppt;

import parsing.common.DocumentParser;

public class PPTExtractionValidator {

    public boolean validate(PPTParseResult result) {

        if (!result.isParseSucceeded()) {
            return false;
        }

        boolean hasSlides =
                result.getSlideCount() > 0;

        boolean hasText =
                result.getTextCount() > 0;

        boolean hasImages =
                result.getImageCount() > 0;

        boolean hasObjects =
                result.getEmbeddedObjectCount() > 0;

        /*
         * A valid PPT should at least contain
         * a slide and some extractable content.
         */

        if (!hasSlides) {

            result.setExtractionValid(false);

            result.setFailureReason(
                    "HSLF completed but no slides were extracted."
            );

            return false;
        }

        if (!hasText &&
                !hasImages &&
                !hasObjects) {

            result.setExtractionValid(false);

            result.setFailureReason(
                    "HSLF completed but no usable content was extracted."
            );

            return false;
        }

        result.setExtractionValid(true);

        return true;
    }
}