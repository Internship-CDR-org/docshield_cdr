package model.ooxml;

import java.net.URI;

/** Format-neutral OPC relationship. */
public class OOXMLRelationship {
    private String sourcePart;
    private String id;
    private String type;
    private String target;
    private String targetMode;

    public OOXMLRelationship() {}

    public OOXMLRelationship(String sourcePart, String id, String type,
                             String target, String targetMode) {
        this.sourcePart = sourcePart;
        this.id = id;
        this.type = type;
        this.target = target;
        this.targetMode = targetMode;
    }

    public String getSourcePart() { return sourcePart; }
    public void setSourcePart(String sourcePart) { this.sourcePart = sourcePart; }
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public String getTargetMode() { return targetMode; }
    public void setTargetMode(String targetMode) { this.targetMode = targetMode; }

    /** Returns true for explicit External relationships and absolute URI targets. */
    public boolean isExternal() {
        if (targetMode != null && targetMode.equalsIgnoreCase("External")) return true;
        if (target == null || target.isBlank()) return false;
        try { return URI.create(target.trim()).isAbsolute(); }
        catch (Exception ignored) { return false; }
    }

    public boolean isInternal() { return !isExternal(); }

    @Override
    public String toString() {
        return "OOXMLRelationship{" +
                "sourcePart='" + sourcePart + '\'' +
                ", id='" + id + '\'' +
                ", type='" + type + '\'' +
                ", target='" + target + '\'' +
                ", targetMode='" + targetMode + '\'' +
                '}';
    }
}
