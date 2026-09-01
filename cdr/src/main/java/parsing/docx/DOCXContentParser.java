package parsing.docx;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class DOCXContentParser {

    public List<String> parseText(Path file)throws IOException {

        List<String> text = new ArrayList<>();

        try (ZipFile zipFile = new ZipFile(file.toFile())) {

            var entry = zipFile.getEntry("word/document.xml");

            if (entry == null) {
                return text;
            }

            try (InputStream inputStream = zipFile.getInputStream(entry)) {

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

                factory.setNamespaceAware(true);

                Document document = factory.newDocumentBuilder().parse(inputStream);

                NodeList textNodes = document.getElementsByTagNameNS("*", "t");

                for (int i = 0; i < textNodes.getLength(); i++) {

                    Node node = textNodes.item(i);

                    String value = node.getTextContent();

                    if (value != null && !value.isBlank()) {
                        text.add(value);
                    }
                }
            }

        } catch (Exception e) {

            throw new IOException(
                    "Failed to extract DOCX content",
                    e
            );
        }

        return text;
    }
}