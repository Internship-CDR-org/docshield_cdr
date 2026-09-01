package parsing.doc;

import parsing.common.DocumentParser;

import org.apache.poi.hwpf.HWPFDocument;
import org.apache.poi.hpsf.SummaryInformation;
import org.apache.poi.hpsf.DocumentSummaryInformation;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public class DOCMetadataParser {

    public Map<String, String> parse(Path file)
            throws IOException {

        Map<String, String> metadata =
                new LinkedHashMap<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HWPFDocument document =
                     new HWPFDocument(inputStream)) {

            SummaryInformation summary =
                    document.getSummaryInformation();

            if (summary != null) {

                add(metadata, "Title",
                        summary.getTitle());

                add(metadata, "Subject",
                        summary.getSubject());

                add(metadata, "Author",
                        summary.getAuthor());

                add(metadata, "Keywords",
                        summary.getKeywords());

                add(metadata, "Comments",
                        summary.getComments());

                add(metadata, "Last Author",
                        summary.getLastAuthor());

                if (summary.getCreateDateTime() != null) {
                    metadata.put(
                            "Created",
                            summary.getCreateDateTime()
                                    .toString()
                    );
                }

                if (summary.getLastSaveDateTime() != null) {
                    metadata.put(
                            "Modified",
                            summary.getLastSaveDateTime()
                                    .toString()
                    );
                }
            }

            DocumentSummaryInformation docSummary =
                    document.getDocumentSummaryInformation();

            if (docSummary != null) {

                add(metadata, "Category",
                        docSummary.getCategory());

                add(metadata, "Company",
                        docSummary.getCompany());

                add(metadata, "Manager",
                        docSummary.getManager());
            }
        }

        return metadata;
    }

    private void add(
            Map<String, String> metadata,
            String key,
            String value) {

        if (value != null
                && !value.isBlank()) {

            metadata.put(key, value);
        }
    }
}