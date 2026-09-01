package parsing.doc;

import parsing.common.DocumentParser;

public class DOCExtractionValidator {

    public boolean validate(DOCParseResult result) {

        if (!result.isParseSucceeded()) {
            return false;
        }

        boolean hasText =
                result.getTextCount() > 0;

        boolean hasImages =
                result.getImageCount() > 0;

        boolean hasObjects =
                result.getEmbeddedObjectCount() > 0;

        if (!hasText && !hasImages && !hasObjects) {

            result.setExtractionValid(false);

            result.setFailureReason(
                    "HWPF completed but extracted no usable content."
            );

            return false;
        }

        result.setExtractionValid(true);

        return true;
    }
}