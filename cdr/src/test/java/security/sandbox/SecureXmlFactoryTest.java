package security.sandbox;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.parsers.DocumentBuilder;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SecureXmlFactoryTest {

    @Test
    void parsesValidXmlSuccessfully() throws Exception {
        String xml = "<root><child>Secure Content</child></root>";
        DocumentBuilder builder = SecureXmlFactory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        assertNotNull(doc);
        assertEquals("root", doc.getDocumentElement().getTagName());
        assertEquals("Secure Content", doc.getElementsByTagName("child").item(0).getTextContent());
    }

    @Test
    void blocksDoctypeDeclarationsAndXxe() throws Exception {
        String xxePayload = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test [
                  <!ENTITY xxe SYSTEM "file:///etc/passwd">
                ]>
                <root><data>&xxe;</data></root>
                """;

        DocumentBuilder builder = SecureXmlFactory.newDocumentBuilder();
        ByteArrayInputStream input = new ByteArrayInputStream(xxePayload.getBytes(StandardCharsets.UTF_8));

        SAXParseException exception = assertThrows(SAXParseException.class, () -> builder.parse(input));
        assertTrue(exception.getMessage().contains("DOCTYPE is disallowed") ||
                   exception.getMessage().contains("disallow-doctype-decl"),
                "Expected DOCTYPE to be disallowed, got: " + exception.getMessage());
    }

    @Test
    void blocksExternalEntityInclusion() throws Exception {
        String billionLaughsBomb = """
                <?xml version="1.0"?>
                <!DOCTYPE lolz [
                 <!ENTITY lol "lol">
                 <!ELEMENT lolz (#PCDATA)>
                 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
                ]>
                <lolz>&lol1;</lolz>
                """;

        DocumentBuilder builder = SecureXmlFactory.newDocumentBuilder();
        ByteArrayInputStream input = new ByteArrayInputStream(billionLaughsBomb.getBytes(StandardCharsets.UTF_8));

        assertThrows(SAXException.class, () -> builder.parse(input));
    }
}
