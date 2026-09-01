package model.common;

public class TestTextComponent {

    public static void main(String[] args) {

        TextComponent text = new TextComponent();

        text.setId("text_001");
        text.setText("Hello Pardhu");
        text.setFontName("Arial");
        text.setFontSize(14);
        text.setBold(true);
        text.setItalic(false);
        text.setAlignment("CENTER");

        System.out.println("ID        : " + text.getId());
        System.out.println("Text      : " + text.getText());
        System.out.println("Font      : " + text.getFontName());
        System.out.println("Size      : " + text.getFontSize());
        System.out.println("Bold      : " + text.isBold());
        System.out.println("Italic    : " + text.isItalic());
        System.out.println("Alignment : " + text.getAlignment());
    }
}