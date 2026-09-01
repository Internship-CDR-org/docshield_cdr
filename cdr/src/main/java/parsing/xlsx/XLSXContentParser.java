package parsing.xlsx;

import parsing.common.DocumentParser;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class XLSXContentParser {

    public List<String> parseCells(Path file)
            throws IOException {

        List<String> cells =
                new ArrayList<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            List<String> sharedStrings =
                    parseSharedStrings(zipFile);

            var entries =
                    zipFile.entries();

            while (entries.hasMoreElements()) {

                ZipEntry entry =
                        entries.nextElement();

                if (entry.isDirectory()) {
                    continue;
                }

                String name =
                        entry.getName();

                if (!name.startsWith(
                        "xl/worksheets/")
                        || !name.endsWith(".xml")) {

                    continue;
                }

                try (InputStream inputStream =
                             zipFile.getInputStream(entry)) {

                    Document document =
                            parseXML(inputStream);

                    NodeList cellNodes =
                            document.getElementsByTagNameNS(
                                    "*",
                                    "c"
                            );

                    for (int i = 0;
                         i < cellNodes.getLength();
                         i++) {

                        Node cell =
                                cellNodes.item(i);

                        Node referenceNode =
                                cell.getAttributes()
                                        .getNamedItem("r");

                        if (referenceNode == null) {
                            continue;
                        }

                        String reference =
                                referenceNode.getNodeValue();

                        Node typeNode =
                                cell.getAttributes()
                                        .getNamedItem("t");

                        String type =
                                typeNode == null
                                        ? ""
                                        : typeNode.getNodeValue();

                        String value =
                                extractCellValue(
                                        cell,
                                        type,
                                        sharedStrings
                                );

                        cells.add(
                                "Cell "
                                        + reference
                                        + " = "
                                        + value
                        );
                    }
                }
            }

        } catch (Exception e) {

            throw new IOException(
                    "Failed to extract XLSX content",
                    e
            );
        }

        return cells;
    }

    private List<String> parseSharedStrings(
            ZipFile zipFile)
            throws Exception {

        List<String> strings =
                new ArrayList<>();

        ZipEntry entry =
                zipFile.getEntry(
                        "xl/sharedStrings.xml"
                );

        if (entry == null) {
            return strings;
        }

        try (InputStream inputStream =
                     zipFile.getInputStream(entry)) {

            Document document =
                    parseXML(inputStream);

            NodeList stringNodes =
                    document.getElementsByTagNameNS(
                            "*",
                            "si"
                    );

            for (int i = 0;
                 i < stringNodes.getLength();
                 i++) {

                Node stringNode =
                        stringNodes.item(i);

                NodeList textNodes =
                        ((org.w3c.dom.Element) stringNode)
                                .getElementsByTagNameNS(
                                        "*",
                                        "t"
                                );

                StringBuilder value =
                        new StringBuilder();

                for (int j = 0;
                     j < textNodes.getLength();
                     j++) {

                    value.append(
                            textNodes
                                    .item(j)
                                    .getTextContent()
                    );
                }

                strings.add(value.toString());
            }
        }

        return strings;
    }

    private String extractCellValue(
            Node cell,
            String type,
            List<String> sharedStrings) {

        NodeList children =
                cell.getChildNodes();

        String rawValue = "";

        for (int i = 0;
             i < children.getLength();
             i++) {

            Node child =
                    children.item(i);

            if ("v".equals(
                    child.getLocalName())) {

                rawValue =
                        child.getTextContent();

                break;
            }
        }

        if ("s".equals(type)) {

            try {

                int index =
                        Integer.parseInt(rawValue);

                if (index >= 0
                        && index < sharedStrings.size()) {

                    return sharedStrings.get(index);
                }

            } catch (NumberFormatException ignored) {
                // Keep raw value
            }
        }

        return rawValue;
    }

    private Document parseXML(
            InputStream inputStream)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        factory.setNamespaceAware(true);

        return factory
                .newDocumentBuilder()
                .parse(inputStream);
    }
}