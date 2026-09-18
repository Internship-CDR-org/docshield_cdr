package parsing.ppt;

import parsing.legacy.LegacyOfficeConverter;
import java.io.IOException;
import java.nio.file.Path;

public class PPTToPPTXConverter {
    public Path convert(Path inputFile) throws IOException {
        return LegacyOfficeConverter.convert(inputFile, "PPT", "pptx");
    }
}
