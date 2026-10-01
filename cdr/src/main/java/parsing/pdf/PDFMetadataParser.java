package parsing.pdf;

import parsing.common.DocumentParser;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

public class PDFMetadataParser {

    public Map<String, String> parse(Path file)
            throws IOException {

        Map<String, String> metadata =
                new java.util.LinkedHashMap<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            PDDocumentInformation info =
                    document.getDocumentInformation();

            metadata.put("Title", info.getTitle());
            metadata.put("Author", info.getAuthor());
            metadata.put("Subject", info.getSubject());
            metadata.put("Keywords", info.getKeywords());
            metadata.put("Creator", info.getCreator());
            metadata.put("Producer", info.getProducer());

            if (info.getCreationDate() != null) {
                metadata.put(
                        "CreationDate",
                        info.getCreationDate().toString()
                );
            }

            if (info.getModificationDate() != null) {
                metadata.put(
                        "ModificationDate",
                        info.getModificationDate().toString()
                );
            }
        }

        return metadata;
    }
}