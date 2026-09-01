package processing.common;

import java.nio.file.Path;

public interface CDRProcessor {

    CDRResult process(
            Path inputFile,
            Path outputFile)
            throws Exception;
}