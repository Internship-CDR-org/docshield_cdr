package model.pptx;

import java.util.LinkedHashMap;
import java.util.Map;

public class PPTXTheme {

    private String name;

    // Theme fonts
    private String majorFont;
    private String minorFont;

    // Theme colors
    private Map<String, String> colors;

    public PPTXTheme() {
        colors = new LinkedHashMap<>();
    }

    // =========================================================
    // NAME
    // =========================================================

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    // =========================================================
    // MAJOR FONT
    // =========================================================

    public String getMajorFont() {
        return majorFont;
    }

    public void setMajorFont(String majorFont) {
        this.majorFont = majorFont;
    }

    // =========================================================
    // MINOR FONT
    // =========================================================

    public String getMinorFont() {
        return minorFont;
    }

    public void setMinorFont(String minorFont) {
        this.minorFont = minorFont;
    }

    // =========================================================
    // COLORS
    // =========================================================

    public Map<String, String> getColors() {
        return colors;
    }

    public void setColor(
            String name,
            String value) {

        colors.put(name, value);
    }

    public String getColor(String name) {
        return colors.get(name);
    }
}