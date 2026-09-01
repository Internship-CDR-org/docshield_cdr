package parsing.common;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class CoreMetadataParser {

    public Map<String, String> parse(Path file)
            throws IOException {

        Map<String, String> metadata =
                new LinkedHashMap<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            ZipEntry entry =
                    zipFile.getEntry("docProps/core.xml");

            if (entry == null) {
                return metadata;
            }

            try (InputStream inputStream =
                         zipFile.getInputStream(entry)) {

                DocumentBuilderFactory factory =
                        DocumentBuilderFactory.newInstance();

                factory.setNamespaceAware(true);

                DocumentBuilder builder =
                        factory.newDocumentBuilder();

                Document document =
                        builder.parse(inputStream);

                addValue(
                        metadata,
                        document,
                        "title"
                );

                addValue(
                        metadata,
                        document,
                        "subject"
                );

                addValue(
                        metadata,
                        document,
                        "creator"
                );

                addValue(
                        metadata,
                        document,
                        "keywords"
                );

                addValue(
                        metadata,
                        document,
                        "description"
                );

                addValue(
                        metadata,
                        document,
                        "created"
                );

                addValue(
                        metadata,
                        document,
                        "modified"
                );
            }

        } catch (Exception e) {

            throw new IOException(
                    "Failed to parse core metadata",
                    e
            );
        }

        return metadata;
    }

    private void addValue(
            Map<String, String> metadata,
            Document document,
            String name) {

        String value = getValue(
                document,
                name
        );

        if (value != null) {
            metadata.put(name, value);
        }
    }

    private String getValue(
            Document document,
            String localName) {

        NodeList nodes =
                document.getElementsByTagNameNS(
                        "*",
                        localName
                );

        if (nodes.getLength() == 0) {
            return null;
        }

        Node node = nodes.item(0);

        return node.getTextContent();
    }
}