package security.sandbox;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Hardened factory for XML parsers providing comprehensive defense against:
 * - XML External Entity (XXE) injection
 * - Denial of Service via entity expansion (Billion Laughs / XML Bomb)
 * - Server-Side Request Forgery (SSRF) via external DTD / schema retrieval
 * - Path traversal / local file disclosure via XML entities
 */
public final class SecureXmlFactory {

    private SecureXmlFactory() { }

    /**
     * Creates and configures a DocumentBuilderFactory with all secure processing
     * flags and external entity resolution disabled.
     */
    public static DocumentBuilderFactory createSecureDocumentBuilderFactory() {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException ignored) { }

        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException ignored) { }

        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } catch (ParserConfigurationException ignored) { }

        try {
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (ParserConfigurationException ignored) { }

        try {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException ignored) { }

        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (IllegalArgumentException ignored) { }

        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) { }

        return factory;
    }

    /**
     * Creates a new DocumentBuilder with the hardened secure configuration.
     */
    public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
        return createSecureDocumentBuilderFactory().newDocumentBuilder();
    }
}
