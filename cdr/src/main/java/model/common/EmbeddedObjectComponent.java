package model.common;

public class EmbeddedObjectComponent {

    private String id;
    private String name;
    private String type;

    private byte[] data;

    private boolean active;

    public EmbeddedObjectComponent() {
    }

    public EmbeddedObjectComponent(
            String id,
            String name,
            String type) {

        this.id = id;
        this.name = name;
        this.type = type;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}