package parsing.pptx;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;

public class PPTXSlideLayoutParser {

    // =========================================================
    // MAIN PARSER
    // =========================================================

    public List<Integer> parse(Path file)
            throws IOException {

        List<Integer> layoutIndices =
                new ArrayList<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            int slideNumber = 1;

            while (true) {

                String relsPath =
                        "ppt/slides/_rels/slide"
                                + slideNumber
                                + ".xml.rels";

                ZipEntry relsEntry =
                        zipFile.getEntry(relsPath);

                /*
                 * Once there is no slideX.xml.rels,
                 * we have reached the end of the slides.
                 */
                if (relsEntry == null) {
                    break;
                }

                int layoutIndex =
                        parseLayoutIndex(
                                zipFile,
                                relsEntry
                        );

                layoutIndices.add(
                        layoutIndex
                );

                slideNumber++;
            }
        }

        return layoutIndices;
    }


    // =========================================================
    // PARSE ONE SLIDE'S RELATIONSHIPS
    // =========================================================

    private int parseLayoutIndex(
            ZipFile zipFile,
            ZipEntry relsEntry)
            throws IOException {

        try (InputStream inputStream =
                    zipFile.getInputStream(relsEntry)) {

            Document document =
                    createDocument(inputStream);

            Element root =
                    document.getDocumentElement();

            NodeList relationships =
                    root.getChildNodes();

            for (int i = 0;
                i < relationships.getLength();
                i++) {

                Node node =
                        relationships.item(i);

                if (!(node instanceof Element)) {
                    continue;
                }

                Element relationship =
                        (Element) node;

                String target =
                        relationship.getAttribute("Target");

                if (target == null ||
                        target.isBlank()) {

                    continue;
                }

                /*
                * We only care about relationships such as:
                *
                * ../slideLayouts/slideLayout2.xml
                */

                if (!target.contains(
                        "slideLayouts/slideLayout")) {

                    continue;
                }

                String fileName =
                        target.substring(
                                target.lastIndexOf('/') + 1
                        );

                /*
                * fileName should now be:
                *
                * slideLayout2.xml
                */

                if (!fileName.startsWith(
                        "slideLayout")) {

                    continue;
                }

                String number =
                        fileName.substring(
                                "slideLayout".length(),
                                fileName.length() - ".xml".length()
                        );

                try {

                    return Integer.parseInt(number);

                } catch (NumberFormatException e) {

                    return 0;
                }
            }
        }

        return 0;
    }

    // =========================================================
    // XML DOCUMENT CREATION
    // =========================================================

    private Document createDocument(
            InputStream inputStream)
            throws IOException {

        try {

            DocumentBuilderFactory factory =
                    DocumentBuilderFactory.newInstance();

            factory.setNamespaceAware(
                    true
            );

            return factory
                    .newDocumentBuilder()
                    .parse(
                            inputStream
                    );

        } catch (Exception e) {

            throw new IOException(
                    "Failed to parse PPTX slide relationships",
                    e
            );
        }
    }
}