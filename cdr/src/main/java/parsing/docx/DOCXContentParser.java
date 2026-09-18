package parsing.docx;


import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import model.common.TextComponent;
import model.common.TextComponent.TextParagraphComponent;
import model.common.TextComponent.TextRunComponent;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class DOCXContentParser {

    public List<TextComponent> parseTextComponents(Path file) throws IOException {

        List<TextComponent> components = new ArrayList<>();

        try (ZipFile zipFile = new ZipFile(file.toFile())) {

            var entry = zipFile.getEntry("word/document.xml");

            if (entry == null) {
                return components;
            }

            try (InputStream inputStream = zipFile.getInputStream(entry)) {

                DocumentBuilderFactory factory = security.sandbox.SecureXmlFactory.createSecureDocumentBuilderFactory();
                factory.setNamespaceAware(true);

                Document document = factory.newDocumentBuilder().parse(inputStream);

                NodeList paragraphs = document.getElementsByTagNameNS("*", "p");

                for (int i = 0; i < paragraphs.getLength(); i++) {

                    Node paragraphNode = paragraphs.item(i);
                    NodeList textNodes = ((org.w3c.dom.Element) paragraphNode)
                            .getElementsByTagNameNS("*", "t");

                    StringBuilder paragraphText = new StringBuilder();
                    for (int j = 0; j < textNodes.getLength(); j++) {
                        String value = textNodes.item(j).getTextContent();
                        if (value != null) {
                            paragraphText.append(value);
                        }
                    }

                    if (paragraphText.isEmpty() || paragraphText.toString().isBlank()) {
                        continue;
                    }

                    TextComponent component = new TextComponent();
                    component.setId("text_" + components.size());
                    component.setText(paragraphText.toString());
                    component.setPageNumber(0);

                    TextParagraphComponent paragraph = new TextParagraphComponent();
                    paragraph.setText(paragraphText.toString());

                    for (int j = 0; j < textNodes.getLength(); j++) {
                        String value = textNodes.item(j).getTextContent();
                        if (value == null || value.isBlank()) {
                            continue;
                        }
                        TextRunComponent run = new TextRunComponent();
                        run.setText(value);
                        paragraph.addRun(run);
                    }

                    component.addParagraph(paragraph);
                    components.add(component);
                }
            }

        } catch (Exception e) {
            throw new IOException("Failed to extract DOCX text components", e);
        }

        return components;
    }

    public List<String> parseText(Path file)throws IOException {

        List<String> text = new ArrayList<>();

        try (ZipFile zipFile = new ZipFile(file.toFile())) {

            var entry = zipFile.getEntry("word/document.xml");

            if (entry == null) {
                return text;
            }

            try (InputStream inputStream = zipFile.getInputStream(entry)) {

                DocumentBuilderFactory factory = security.sandbox.SecureXmlFactory.createSecureDocumentBuilderFactory();

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