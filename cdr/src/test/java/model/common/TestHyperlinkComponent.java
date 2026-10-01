package model.common;

public class TestHyperlinkComponent {

    public static void main(String[] args) {

        // Hyperlink with visible text
        HyperlinkComponent link1 =
                new HyperlinkComponent(
                        "link_001",
                        "GitHub",
                        "https://github.com"
                );

        // Hyperlink without visible display text
        HyperlinkComponent link2 =
                new HyperlinkComponent(
                        "link_002",
                        null,
                        "https://example.com"
                );

        System.out.println("========== LINK 1 ==========");
        System.out.println("ID          : " + link1.getId());
        System.out.println("Display     : " + link1.getDisplayText());
        System.out.println("Target      : " + link1.getTarget());

        System.out.println();

        System.out.println("========== LINK 2 ==========");
        System.out.println("ID          : " + link2.getId());
        System.out.println("Display     : " + link2.getDisplayText());
        System.out.println("Target      : " + link2.getTarget());
    }
}