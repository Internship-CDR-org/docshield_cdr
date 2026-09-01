package model.common;

public class ThreatComponent {

    private String id;
    private String ruleId;
    private String category;

    private String severity;
    private String description;

    private String action;

    private String componentId;

    public ThreatComponent() {
    }

    public ThreatComponent(
            String id,
            String ruleId,
            String category,
            String severity,
            String description,
            String action,
            String componentId) {

        this.id = id;
        this.ruleId = ruleId;
        this.category = category;
        this.severity = severity;
        this.description = description;
        this.action = action;
        this.componentId = componentId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getComponentId() {
        return componentId;
    }

    public void setComponentId(String componentId) {
        this.componentId = componentId;
    }
}