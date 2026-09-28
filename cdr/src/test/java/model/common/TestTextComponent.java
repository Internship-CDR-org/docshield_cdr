package model.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TestTextComponent {

    @Test
    void testGettersAndSetters() {
        TextComponent text = new TextComponent();

        text.setId("text_001");
        text.setText("Sample text for test");
        text.setFontName("Arial");
        text.setFontSize(14);
        text.setBold(true);
        text.setItalic(false);
        text.setAlignment("CENTER");

        assertEquals("text_001", text.getId());
        assertEquals("Sample text for test", text.getText());
        assertEquals("Arial", text.getFontName());
        assertEquals(14, text.getFontSize());
        assertTrue(text.isBold());
        assertFalse(text.isItalic());
        assertEquals("CENTER", text.getAlignment());
    }
}