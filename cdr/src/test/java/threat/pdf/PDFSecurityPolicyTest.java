package threat.pdf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PDFSecurityPolicyTest {
    @Test
    void detectsPercentEncodedJavascriptScheme() {
        assertTrue(PDFSecurityPolicy.isDangerousUri("%6A%61%76%61%73%63%72%69%70%74:alert(1)"));
    }

    @Test
    void detectsLeadingControlCharacters() {
        assertTrue(PDFSecurityPolicy.isDangerousUri("\u0000  javascript:alert(1)"));
    }

    @Test
    void preservesOrdinaryHttps() {
        assertFalse(PDFSecurityPolicy.isDangerousUri("https://example.com/path?a=1+2"));
    }

    @Test
    void exposesConservativeSafetyLimits() {
        assertTrue(PDFSecurityPolicy.MAX_INPUT_BYTES > 0);
        assertTrue(PDFSecurityPolicy.MAX_COS_OBJECTS > 0);
        assertTrue(PDFSecurityPolicy.MAX_EMBEDDED_PAYLOAD_BYTES > 0);
        assertTrue(PDFSecurityPolicy.MAX_PAGES > 0);
        assertTrue(PDFSecurityPolicy.MAX_COS_GRAPH_DEPTH > 0);
    }
}
