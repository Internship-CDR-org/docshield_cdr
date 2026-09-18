package parsing.xls;

import parsing.legacy.LegacyOfficeConverter;
import java.io.IOException;
import java.nio.file.Path;

public class XLSToXLSXConverter {
    public Path convert(Path inputFile) throws IOException {
        return LegacyOfficeConverter.convert(inputFile, "XLS", "xlsx");
    }
}
