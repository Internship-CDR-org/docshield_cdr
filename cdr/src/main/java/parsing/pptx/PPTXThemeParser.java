package parsing.pptx;

import parsing.common.DocumentParser;

import model.pptx.PPTXTheme;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class PPTXThemeParser {

    public PPTXTheme parse(Path file)
            throws IOException {

        PPTXTheme theme =
                new PPTXTheme();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            ZipEntry entry =
                    zipFile.getEntry(
                            "ppt/theme/theme1.xml"
                    );

            if (entry == null) {
                return theme;
            }

            try (InputStream inputStream =
                         zipFile.getInputStream(entry)) {

                try {

                    DocumentBuilderFactory factory =
                            DocumentBuilderFactory.newInstance();

                    factory.setNamespaceAware(true);

                    Document document =
                            factory.newDocumentBuilder()
                                    .parse(inputStream);

                    Element root =
                            document.getDocumentElement();


                    // =================================================
                    // THEME NAME
                    // =================================================

                    String themeName =
                            root.getAttribute("name");

                    if (themeName != null &&
                            !themeName.isBlank()) {

                        theme.setName(
                                themeName
                        );
                    }


                    // =================================================
                    // THEME ELEMENTS
                    // =================================================

                    Element themeElements =
                            getFirstChild(
                                    root,
                                    "themeElements"
                            );

                    if (themeElements == null) {
                        return theme;
                    }


                    // =================================================
                    // COLOR SCHEME
                    // =================================================

                    Element colorScheme =
                            getFirstChild(
                                    themeElements,
                                    "clrScheme"
                            );

                    if (colorScheme != null) {

                        parseColors(
                                colorScheme,
                                theme
                        );
                    }


                    // =================================================
                    // FONT SCHEME
                    // =================================================

                    Element fontScheme =
                            getFirstChild(
                                    themeElements,
                                    "fontScheme"
                            );

                    if (fontScheme != null) {

                        parseFonts(
                                fontScheme,
                                theme
                        );
                    }

                } catch (ParserConfigurationException |
                         SAXException e) {

                    throw new IOException(
                            "Failed to parse PPTX theme",
                            e
                    );
                }
            }
        }

        return theme;
    }


    // =============================================================
    // COLORS
    // =============================================================

    private void parseColors(
            Element colorScheme,
            PPTXTheme theme) {

        String[] colorNames = {
                "dk1",
                "lt1",
                "dk2",
                "lt2",
                "accent1",
                "accent2",
                "accent3",
                "accent4",
                "accent5",
                "accent6",
                "hlink",
                "folHlink"
        };

        for (String colorName :
                colorNames) {

            Element colorElement =
                    getFirstChild(
                            colorScheme,
                            colorName
                    );

            if (colorElement == null) {
                continue;
            }

            String value =
                    extractColorValue(
                            colorElement
                    );

            if (value != null &&
                    !value.isBlank()) {

                theme.setColor(
                        colorName,
                        value
                );
            }
        }
    }


    // =============================================================
    // COLOR VALUE
    // =============================================================

    private String extractColorValue(
            Element colorElement) {

        NodeList children =
                colorElement.getChildNodes();

        for (int i = 0;
             i < children.getLength();
             i++) {

            Node node =
                    children.item(i);

            if (!(node instanceof Element)) {
                continue;
            }

            Element element =
                    (Element) node;

            String localName =
                    element.getLocalName();

            if ("srgbClr".equals(localName)) {

                return element.getAttribute(
                        "val"
                );
            }

            if ("sysClr".equals(localName)) {

                String lastColor =
                        element.getAttribute(
                                "lastClr"
                        );

                if (lastColor != null &&
                        !lastColor.isBlank()) {

                    return lastColor;
                }

                return element.getAttribute(
                        "val"
                );
            }
        }

        return null;
    }


    // =============================================================
    // FONTS
    // =============================================================

    private void parseFonts(
            Element fontScheme,
            PPTXTheme theme) {

        Element majorFont =
                getFirstChild(
                        fontScheme,
                        "majorFont"
                );

        Element minorFont =
                getFirstChild(
                        fontScheme,
                        "minorFont"
                );


        // ---------------------------------------------------------
        // MAJOR FONT
        // ---------------------------------------------------------

        if (majorFont != null) {

            Element latin =
                    getFirstChild(
                            majorFont,
                            "latin"
                    );

            if (latin != null) {

                String typeface =
                        latin.getAttribute(
                                "typeface"
                        );

                if (typeface != null &&
                        !typeface.isBlank()) {

                    theme.setMajorFont(
                            typeface
                    );
                }
            }
        }


        // ---------------------------------------------------------
        // MINOR FONT
        // ---------------------------------------------------------

        if (minorFont != null) {

            Element latin =
                    getFirstChild(
                            minorFont,
                            "latin"
                    );

            if (latin != null) {

                String typeface =
                        latin.getAttribute(
                                "typeface"
                        );

                if (typeface != null &&
                        !typeface.isBlank()) {

                    theme.setMinorFont(
                            typeface
                    );
                }
            }
        }
    }


    // =============================================================
    // FIND CHILD ELEMENT
    // =============================================================

    private Element getFirstChild(
            Element parent,
            String localName) {

        NodeList children =
                parent.getChildNodes();

        for (int i = 0;
             i < children.getLength();
             i++) {

            Node node =
                    children.item(i);

            if (!(node instanceof Element)) {
                continue;
            }

            Element element =
                    (Element) node;

            if (localName.equals(
                    element.getLocalName())) {

                return element;
            }
        }

        return null;
    }
}