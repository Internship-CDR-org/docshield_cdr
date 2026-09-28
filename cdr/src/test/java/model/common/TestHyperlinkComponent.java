package model.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TestHyperlinkComponent {

    @Test
    void testHyperlinkWithDisplayText() {
        HyperlinkComponent link = new HyperlinkComponent(
                "link_001",
                "Example Site",
                "https://example.com"
        );

        assertEquals("link_001", link.getId());
        assertEquals("Example Site", link.getDisplayText());
        assertEquals("https://example.com", link.getTarget());
    }

    @Test
    void testHyperlinkWithoutDisplayText() {
        HyperlinkComponent link = new HyperlinkComponent(
                "link_002",
                null,
                "https://example.com"
        );

        assertEquals("link_002", link.getId());
        assertNull(link.getDisplayText());
        assertEquals("https://example.com", link.getTarget());
    }
}