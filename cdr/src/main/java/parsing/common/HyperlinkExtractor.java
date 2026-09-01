package parsing.common;

import model.common.HyperlinkComponent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public interface HyperlinkExtractor {

    List<HyperlinkComponent> extract(Path file)
            throws IOException;
}