package parsing.pptx;

import parsing.common.DocumentParser;

import model.pptx.PPTXLayout;
import model.pptx.PPTXLayoutElement;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
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

public class PPTXLayoutParser {

    private static final String RELATIONSHIP_NAMESPACE =
            "http://schemas.openxmlformats.org/package/2006/relationships";

    private static final String OFFICE_RELATIONSHIP_NAMESPACE =
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships";


    // =============================================================
    // MAIN PARSER
    // =============================================================

    public List<PPTXLayout> parse(Path file)
            throws IOException {

        List<PPTXLayout> layouts =
                new ArrayList<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            /*
             * We don't assume that all nine layouts always exist.
             *
             * We check each possible layout and only add the
             * layouts that are actually present in the PPTX.
             */

            for (int i = 1; i <= 9; i++) {

                String layoutPath =
                        "ppt/slideLayouts/slideLayout"
                                + i
                                + ".xml";

                ZipEntry entry =
                        zipFile.getEntry(layoutPath);

                if (entry == null) {
                    continue;
                }

                PPTXLayout layout =
                        parseLayout(
                                zipFile,
                                i
                        );

                if (layout != null) {

                    layouts.add(
                            layout
                    );
                }
            }
        }

        return layouts;
    }


    // =============================================================
    // PARSE ONE LAYOUT
    // =============================================================

    private PPTXLayout parseLayout(
            ZipFile zipFile,
            int index)
            throws IOException {

        String layoutPath =
                "ppt/slideLayouts/slideLayout"
                        + index
                        + ".xml";

        ZipEntry layoutEntry =
                zipFile.getEntry(layoutPath);

        if (layoutEntry == null) {
            return null;
        }

        try (InputStream inputStream =
                     zipFile.getInputStream(
                             layoutEntry
                     )) {

            Document document =
                    createDocument(
                            inputStream
                    );

            Element root =
                    document.getDocumentElement();

            /*
             * <p:cSld>
             *
             * This contains the actual common slide
             * content belonging to the layout.
             */

            Element commonSlideData =
                    getFirstChild(
                            root,
                            "cSld"
                    );

            if (commonSlideData == null) {
                return null;
            }

            PPTXLayout layout =
                    new PPTXLayout();

            layout.setIndex(
                    index
            );

            String name =
                    commonSlideData.getAttribute(
                            "name"
                    );

            if (name == null ||
                    name.isBlank()) {

                name =
                        "Layout " + index;
            }

            layout.setName(
                    name
            );


            // =====================================================
            // SHAPES / IMAGES
            // =====================================================

            parseShapeTree(
                    zipFile,
                    index,
                    commonSlideData,
                    layout
            );

            return layout;
        }
    }


    // =============================================================
    // PARSE SHAPE TREE
    // =============================================================

    private void parseShapeTree(
            ZipFile zipFile,
            int layoutIndex,
            Element commonSlideData,
            PPTXLayout layout)
            throws IOException {

        Element shapeTree =
                getFirstChild(
                        commonSlideData,
                        "spTree"
                );

        if (shapeTree == null) {
            return;
        }

        NodeList children =
                shapeTree.getChildNodes();

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


            // =====================================================
            // PICTURE
            // =====================================================

            if ("pic".equals(localName)) {

                PPTXLayoutElement picture =
                        parsePicture(
                                zipFile,
                                layoutIndex,
                                element
                        );

                if (picture != null) {

                    layout.addElement(
                            picture
                    );
                }
            }


            // =====================================================
            // SHAPE
            // =====================================================

            else if ("sp".equals(localName)) {

                PPTXLayoutElement shape =
                        parseShape(
                                element
                        );

                if (shape != null) {

                    layout.addElement(
                            shape
                    );
                }
            }
        }
    }


    // =============================================================
    // PARSE PICTURE
    // =============================================================

    private PPTXLayoutElement parsePicture(
            ZipFile zipFile,
            int layoutIndex,
            Element picture)
            throws IOException {

        PPTXLayoutElement result =
                new PPTXLayoutElement();

        result.setType(
                PPTXLayoutElement.Type.IMAGE
        );


        // =========================================================
        // GET RELATIONSHIP ID
        // =========================================================

        Element blip =
                findFirstElement(
                        picture,
                        "blip"
                );

        if (blip != null) {

            String relationshipId =
                    blip.getAttributeNS(
                            OFFICE_RELATIONSHIP_NAMESPACE,
                            "embed"
                    );

            /*
             * Resolve:
             *
             * rId2
             *   ↓
             * ../media/image1.png
             *   ↓
             * ppt/media/image1.png
             */

            String resource =
                    resolveResource(
                            zipFile,
                            layoutIndex,
                            relationshipId
                    );

            result.setResource(
                    resource
            );
        }


        // =========================================================
        // POSITION / SIZE
        // =========================================================

        setTransform(
                picture,
                result
        );

        return result;
    }


    // =============================================================
    // RESOLVE RELATIONSHIP
    // =============================================================

    private String resolveResource(
            ZipFile zipFile,
            int layoutIndex,
            String relationshipId)
            throws IOException {

        if (relationshipId == null ||
                relationshipId.isBlank()) {

            return null;
        }

        String relsPath =
                "ppt/slideLayouts/_rels/slideLayout"
                        + layoutIndex
                        + ".xml.rels";

        ZipEntry relsEntry =
                zipFile.getEntry(
                        relsPath
                );

        if (relsEntry == null) {
            return null;
        }

        try (InputStream inputStream =
                     zipFile.getInputStream(
                             relsEntry
                     )) {

            Document document =
                    createDocument(
                            inputStream
                    );

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

                String id =
                        relationship.getAttribute(
                                "Id"
                        );

                if (!relationshipId.equals(id)) {
                    continue;
                }


                // =================================================
                // MAKE SURE THIS IS AN IMAGE RELATIONSHIP
                // =================================================

                String type =
                        relationship.getAttribute(
                                "Type"
                        );

                if (type == null ||
                        !type.endsWith(
                                "/image"
                        )) {

                    return null;
                }


                // =================================================
                // TARGET
                // =================================================

                String target =
                        relationship.getAttribute(
                                "Target"
                        );

                if (target == null ||
                        target.isBlank()) {

                    return null;
                }


                /*
                 * For a layout relationship:
                 *
                 * ../media/image1.png
                 *
                 * becomes:
                 *
                 * ppt/media/image1.png
                 */

                if (target.startsWith("../")) {

                    target =
                            target.substring(
                                    3
                            );

                    return "ppt/" + target;
                }


                /*
                 * Handle a target that is already
                 * package-relative.
                 */

                if (target.startsWith("/")) {

                    return target.substring(
                            1
                    );
                }


                return target;
            }
        }

        return null;
    }


    // =============================================================
    // PARSE SHAPE
    // =============================================================

    private PPTXLayoutElement parseShape(
            Element shape) {

        PPTXLayoutElement result =
                new PPTXLayoutElement();

        result.setType(
                PPTXLayoutElement.Type.SHAPE
        );


        // =========================================================
        // POSITION / SIZE
        // =========================================================

        setTransform(
                shape,
                result
        );


        // =========================================================
        // FILL
        // =========================================================

        Element solidFill =
                findFirstElement(
                        shape,
                        "solidFill"
                );

        if (solidFill != null) {

            Element color =
                    findFirstElement(
                            solidFill,
                            "srgbClr"
                    );

            if (color != null) {

                String fillColor =
                        color.getAttribute(
                                "val"
                        );

                if (fillColor != null &&
                        !fillColor.isBlank()) {

                    result.setFillColor(
                            fillColor
                    );
                }


                // =================================================
                // TRANSPARENCY
                // =================================================

                Element alpha =
                        findFirstElement(
                                color,
                                "alpha"
                        );

                if (alpha != null) {

                    String value =
                            alpha.getAttribute(
                                    "val"
                            );

                    if (value != null &&
                            !value.isBlank()) {

                        try {

                            result.setAlpha(
                                    Integer.parseInt(
                                            value
                                    )
                            );

                        } catch (
                                NumberFormatException ignored) {

                            /*
                             * Keep default alpha:
                             *
                             * 100000 = fully opaque
                             */
                        }
                    }
                }
            }
        }

        return result;
    }


    // =============================================================
    // SET TRANSFORM
    // =============================================================

    private void setTransform(
            Element element,
            PPTXLayoutElement result) {

        Element transform =
                findFirstElement(
                        element,
                        "xfrm"
                );

        if (transform == null) {
            return;
        }


        // =========================================================
        // OFFSET
        // =========================================================

        Element offset =
                findFirstElement(
                        transform,
                        "off"
                );

        if (offset != null) {

            result.setX(
                    parseLong(
                            offset.getAttribute(
                                    "x"
                            )
                    )
            );

            result.setY(
                    parseLong(
                            offset.getAttribute(
                                    "y"
                            )
                    )
            );
        }


        // =========================================================
        // EXTENT
        // =========================================================

        Element extent =
                findFirstElement(
                        transform,
                        "ext"
                );

        if (extent != null) {

            result.setWidth(
                    parseLong(
                            extent.getAttribute(
                                    "cx"
                            )
                    )
            );

            result.setHeight(
                    parseLong(
                            extent.getAttribute(
                                    "cy"
                            )
                    )
            );
        }
    }


    // =============================================================
    // CREATE XML DOCUMENT
    // =============================================================

    private Document createDocument(
            InputStream inputStream)
            throws IOException {

        try {

            DocumentBuilderFactory factory =
                    DocumentBuilderFactory.newInstance();

            /*
             * OOXML uses namespaces, so this is required
             * for getLocalName() and getAttributeNS().
             */

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
                    "Failed to parse PPTX layout XML",
                    e
            );
        }
    }


    // =============================================================
    // GET FIRST DIRECT CHILD
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
                    element.getLocalName()
            )) {

                return element;
            }
        }

        return null;
    }


    // =============================================================
    // FIND FIRST DESCENDANT
    // =============================================================

    private Element findFirstElement(
            Element parent,
            String localName) {

        NodeList nodes =
                parent.getElementsByTagNameNS(
                        "*",
                        localName
                );

        if (nodes.getLength() == 0) {
            return null;
        }

        return (Element) nodes.item(0);
    }


    // =============================================================
    // PARSE LONG
    // =============================================================

    private long parseLong(
            String value) {

        if (value == null ||
                value.isBlank()) {

            return 0;
        }

        try {

            return Long.parseLong(
                    value
            );

        } catch (NumberFormatException e) {

            return 0;
        }
    }
}