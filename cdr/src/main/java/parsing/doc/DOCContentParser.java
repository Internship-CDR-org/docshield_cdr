package parsing.doc;

import parsing.common.DocumentParser;

import org.apache.poi.hwpf.HWPFDocument;
import org.apache.poi.hwpf.extractor.WordExtractor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DOCContentParser {

    public List<String> parseText(Path file)
            throws IOException {

        List<String> content =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HWPFDocument document =
                     new HWPFDocument(inputStream);
             WordExtractor extractor =
                     new WordExtractor(document)) {

            String text =
                    extractor.getText();

            if (text != null
                    && !text.isBlank()) {

                content.add(text.trim());
            }
        }

        return content;
    }
}