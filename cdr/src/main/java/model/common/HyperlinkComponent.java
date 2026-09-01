package model.common;

public class HyperlinkComponent {

    private String id;
    private String displayText;
    private String target;

    public HyperlinkComponent() {
    }

    public HyperlinkComponent(
            String id,
            String displayText,
            String target) {

        this.id = id;
        this.displayText = displayText;
        this.target = target;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDisplayText() {
        return displayText;
    }

    public void setDisplayText(String displayText) {
        this.displayText = displayText;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }
}