package parsing.pptx;

import parsing.common.DocumentParser;

import model.ooxml.OOXMLPart;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


/**
 * Performs deep structural inspection of XML-based PPTX parts.
 *
 * This class DOES NOT modify the original OOXMLPart.
 *
 * The original raw bytes remain untouched.
 *
 * The XML is parsed only into a temporary DOM representation
 * for inspection.
 */
public class PPTXXmlInspector {


    // =========================================================
    // XML INSPECTION RESULT
    // =========================================================

    public static class XmlInspectionResult {

        private final OOXMLPart part;

        private String rootElement;

        private final Set<String> namespaces =
                new LinkedHashSet<>();

        private final Set<String> elementNames =
                new LinkedHashSet<>();

        private final Set<String> attributeNames =
                new LinkedHashSet<>();

        private final List<String> externalReferences =
                new ArrayList<>();

        private boolean xmlParsed;

        private String parseError;


        public XmlInspectionResult(
                OOXMLPart part) {

            this.part = part;
        }


        public OOXMLPart getPart() {

            return part;
        }


        public String getPartName() {

            return part == null
                    ? null
                    : part.getPartName();
        }


        public String getRootElement() {

            return rootElement;
        }


        public Set<String> getNamespaces() {

            return namespaces;
        }


        public Set<String> getElementNames() {

            return elementNames;
        }


        public Set<String> getAttributeNames() {

            return attributeNames;
        }


        public List<String> getExternalReferences() {

            return externalReferences;
        }


        public boolean isXmlParsed() {

            return xmlParsed;
        }


        public String getParseError() {

            return parseError;
        }


        private void setRootElement(
                String rootElement) {

            this.rootElement = rootElement;
        }


        private void setXmlParsed(
                boolean xmlParsed) {

            this.xmlParsed = xmlParsed;
        }


        private void setParseError(
                String parseError) {

            this.parseError = parseError;
        }
    }


    // =========================================================
    // PUBLIC API
    // =========================================================

    /**
     * Inspects one XML package part.
     */
    public XmlInspectionResult inspect(
            OOXMLPart part) {

        XmlInspectionResult result =
                new XmlInspectionResult(
                        part
                );


        if (part == null) {

            result.setParseError(
                    "Part is null."
            );

            return result;
        }


        byte[] data =
                part.getData();


        if (data == null ||
                data.length == 0) {

            result.setParseError(
                    "XML part contains no data."
            );

            return result;
        }


        try {

            Document document =
                    parseXml(
                            data
                    );


            Element root =
                    document.getDocumentElement();


            if (root == null) {

                result.setParseError(
                        "XML document has no root element."
                );

                return result;
            }


            result.setXmlParsed(
                    true
            );


            String rootName =
                    getElementName(
                            root
                    );


            result.setRootElement(
                    rootName
            );


            inspectElement(
                    root,
                    result
            );


        } catch (Exception e) {

            result.setParseError(
                    e.getMessage()
            );
        }


        return result;
    }


    // =========================================================
    // ELEMENT INSPECTION
    // =========================================================

    private void inspectElement(
            Element element,
            XmlInspectionResult result) {

        if (element == null) {
            return;
        }


        // -----------------------------------------------------
        // Element name
        // -----------------------------------------------------

        String elementName =
                getElementName(
                        element
                );


        if (elementName != null) {

            result.elementNames.add(
                    elementName
            );
        }


        // -----------------------------------------------------
        // Namespace
        // -----------------------------------------------------

        String namespace =
                element.getNamespaceURI();


        if (namespace != null &&
                !namespace.isBlank()) {

            result.namespaces.add(
                    namespace
            );
        }


        // -----------------------------------------------------
        // Attributes
        // -----------------------------------------------------

        NamedNodeMap attributes =
                element.getAttributes();


        for (int i = 0;
             i < attributes.getLength();
             i++) {

            Node attribute =
                    attributes.item(i);


            String attributeName =
                    attribute.getNodeName();


            if (attributeName != null) {

                result.attributeNames.add(
                        attributeName
                );
            }


            String attributeNamespace =
                    attribute.getNamespaceURI();


            if (attributeNamespace != null &&
                    !attributeNamespace.isBlank()) {

                result.namespaces.add(
                        attributeNamespace
                );
            }


            // ---------------------------------------------
            // Detect obvious external references.
            //
            // This is ONLY evidence collection.
            // It does not declare the reference malicious.
            // ---------------------------------------------

            String value =
                    attribute.getNodeValue();


            if (value != null &&
                    looksLikeExternalReference(
                            attributeName,
                            value
                    )) {

                result.externalReferences.add(
                        attributeName +
                        " = " +
                        value
                );
            }
        }


        // -----------------------------------------------------
        // Child elements
        // -----------------------------------------------------

        NodeList children =
                element.getChildNodes();


        for (int i = 0;
             i < children.getLength();
             i++) {

            Node child =
                    children.item(i);


            if (child instanceof Element) {

                inspectElement(
                        (Element) child,
                        result
                );
            }
        }
    }


    // =========================================================
    // EXTERNAL REFERENCE DETECTION
    // =========================================================

    /**
     * Collects attributes that may contain external references.
     *
     * This is deliberately broad.
     *
     * A later security layer will decide whether the reference
     * is actually dangerous.
     */
    private boolean looksLikeExternalReference(
            String attributeName,
            String value) {

        if (attributeName == null ||
                value == null) {

            return false;
        }


        String attribute =
                attributeName
                        .trim()
                        .toLowerCase();


        String normalizedValue =
                value
                        .trim()
                        .toLowerCase();


        // ---------------------------------------------------------
        // XML namespace declarations are NOT external references.
        // ---------------------------------------------------------

        if (attribute.equals("xmlns") ||
                attribute.startsWith("xmlns:")) {

            return false;
        }


        // ---------------------------------------------------------
        // Namespace URI values should not independently be treated
        // as external references.
        // ---------------------------------------------------------

        if (attribute.equals("uri") &&
                normalizedValue.startsWith(
                        "http://schemas."
                )) {

            return false;
        }


        // ---------------------------------------------------------
        // Relationship / hyperlink style attributes
        // ---------------------------------------------------------

        if (attribute.equals("target")) {

            return true;
        }


        if (attribute.equals("href") ||
                attribute.endsWith(":href")) {

            return true;
        }


        // ---------------------------------------------------------
        // Explicit URL-like values
        // ---------------------------------------------------------

        if (normalizedValue.startsWith(
                "http://"
        )) {

            return true;
        }


        if (normalizedValue.startsWith(
                "https://"
        )) {

            return true;
        }


        if (normalizedValue.startsWith(
                "ftp://"
        )) {

            return true;
        }


        if (normalizedValue.startsWith(
                "file:"
        )) {

            return true;
        }


        if (normalizedValue.startsWith(
                "data:"
        )) {

            return true;
        }


        return false;
    }

    // =========================================================
    // XML PARSING
    // =========================================================

    private Document parseXml(
            byte[] data)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();


        factory.setNamespaceAware(
                true
        );


        try {
            factory.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl",
                    true
            );
        } catch (Exception ignored) {
        }


        try {
            factory.setFeature(
                    "http://xml.org/sax/features/external-general-entities",
                    false
            );
        } catch (Exception ignored) {
        }


        try {
            factory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities",
                    false
            );
        } catch (Exception ignored) {
        }


        try {
            factory.setXIncludeAware(
                    false
            );
        } catch (Exception ignored) {
        }


        try {
            factory.setExpandEntityReferences(
                    false
            );
        } catch (Exception ignored) {
        }


        DocumentBuilder builder =
                factory.newDocumentBuilder();


        try (ByteArrayInputStream input =
                     new ByteArrayInputStream(
                             data
                     )) {

            return builder.parse(
                    input
            );
        }
    }


    // =========================================================
    // ELEMENT NAME
    // =========================================================

    private String getElementName(
            Element element) {

        if (element == null) {
            return null;
        }


        String localName =
                element.getLocalName();


        if (localName != null &&
                !localName.isBlank()) {

            return localName;
        }


        return element.getNodeName();
    }
}