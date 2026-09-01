package parsing.ppt;

import parsing.common.DocumentParser;

import org.apache.poi.hpsf.DocumentSummaryInformation;
import org.apache.poi.hpsf.SummaryInformation;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class PPTMetadataParser {

    public Map<String, String> parseCoreMetadata(
            Path file) throws IOException {

        Map<String, String> metadata =
                new java.util.LinkedHashMap<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSLFSlideShow slideshow =
                     new HSLFSlideShow(inputStream)) {

            SummaryInformation summary =
                    slideshow.getSummaryInformation();

            if (summary != null) {

                add(metadata, "title",
                        summary.getTitle());

                add(metadata, "subject",
                        summary.getSubject());

                add(metadata, "author",
                        summary.getAuthor());

                add(metadata, "keywords",
                        summary.getKeywords());

                add(metadata, "comments",
                        summary.getComments());

                add(metadata, "lastAuthor",
                        summary.getLastAuthor());

                add(metadata, "applicationName",
                        summary.getApplicationName());
            }


            DocumentSummaryInformation documentSummary =
                    slideshow.getDocumentSummaryInformation();

            if (documentSummary != null) {

                add(metadata, "category",
                        documentSummary.getCategory());

                add(metadata, "company",
                        documentSummary.getCompany());

                add(metadata, "manager",
                        documentSummary.getManager());
            }
        }

        return metadata;
    }


    private void add(
            Map<String, String> metadata,
            String key,
            String value) {

        if (value != null &&
                !value.isBlank()) {

            metadata.put(key, value);
        }
    }
}