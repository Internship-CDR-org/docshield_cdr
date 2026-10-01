package parsing.common;

import model.common.HyperlinkComponent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Common contract for format-specific hyperlink extraction.
 *
 * <p>The interface is retained because the RTF parser uses it. Legacy
 * Office-specific HSLF/HSSF implementations are intentionally not retained;
 * DOC/PPT/XLS inputs are converted through the isolated LibreOffice boundary
 * and then use their modern OOXML parsers.</p>
 */
public interface HyperlinkExtractor {

    List<HyperlinkComponent> extract(Path file) throws IOException;
}
