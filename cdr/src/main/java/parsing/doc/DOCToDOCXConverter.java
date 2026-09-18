package parsing.doc;

import parsing.legacy.LegacyOfficeConverter;
import java.io.IOException;
import java.nio.file.Path;

public class DOCToDOCXConverter {
    public Path convert(Path inputFile) throws IOException {
        return LegacyOfficeConverter.convert(inputFile, "DOC", "docx");
    }
}
