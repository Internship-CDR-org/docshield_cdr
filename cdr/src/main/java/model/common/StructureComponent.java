package model.common;

import java.util.ArrayList;
import java.util.List;

public class StructureComponent {

    // =========================================================
    // BASIC IDENTITY
    // =========================================================

    private String id;
    private String type;
    private String name;

    private int index;
    private int slideNumber;

    // =========================================================
    // POSITION / SIZE
    // =========================================================

    private long x;
    private long y;
    private long width;
    private long height;

    // =========================================================
    // VISUAL STYLE
    // =========================================================

    private String fillColor;
    private int fillAlpha = 100000;

    private String lineColor;
    private int lineAlpha = 100000;

    private double lineWidth;

    // =========================================================
    // EXACT SHAPE GEOMETRY
    // =========================================================

    private String presetGeometry;

    private String geometryAdjustment;

    /*
     * PowerPoint rotation:
     * 60000 = 1 degree
     */
    private Integer rotation;

    // =========================================================
    // GENERIC DRAWINGML
    // =========================================================

    /*
     * Raw DrawingML fragments which are not represented by
     * the semantic IR yet.
     *
     * Examples:
     *
     * <a:effectLst>...</a:effectLst>
     * <a:effectDag>...</a:effectDag>
     * other DrawingML information
     *
     * We preserve these instead of interpreting every
     * PowerPoint feature individually.
     */
    private List<String> drawingXml =
            new ArrayList<>();

    // =========================================================
    // CONSTRUCTORS
    // =========================================================

    public StructureComponent() {
    }

    public StructureComponent(
            String id,
            String type,
            String name,
            int index) {

        this.id = id;
        this.type = type;
        this.name = name;
        this.index = index;
    }

    // =========================================================
    // BASIC IDENTITY
    // =========================================================

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public int getSlideNumber() {
        return slideNumber;
    }

    public void setSlideNumber(int slideNumber) {
        this.slideNumber = slideNumber;
    }

    // =========================================================
    // POSITION / SIZE
    // =========================================================

    public long getX() {
        return x;
    }

    public void setX(long x) {
        this.x = x;
    }

    public long getY() {
        return y;
    }

    public void setY(long y) {
        this.y = y;
    }

    public long getWidth() {
        return width;
    }

    public void setWidth(long width) {
        this.width = width;
    }

    public long getHeight() {
        return height;
    }

    public void setHeight(long height) {
        this.height = height;
    }

    // =========================================================
    // FILL
    // =========================================================

    public String getFillColor() {
        return fillColor;
    }

    public void setFillColor(String fillColor) {
        this.fillColor = fillColor;
    }

    public int getFillAlpha() {
        return fillAlpha;
    }

    public void setFillAlpha(int fillAlpha) {
        this.fillAlpha = fillAlpha;
    }

    // =========================================================
    // LINE
    // =========================================================

    public String getLineColor() {
        return lineColor;
    }

    public void setLineColor(String lineColor) {
        this.lineColor = lineColor;
    }

    public int getLineAlpha() {
        return lineAlpha;
    }

    public void setLineAlpha(int lineAlpha) {
        this.lineAlpha = lineAlpha;
    }

    public double getLineWidth() {
        return lineWidth;
    }

    public void setLineWidth(double lineWidth) {
        this.lineWidth = lineWidth;
    }

    // =========================================================
    // GEOMETRY
    // =========================================================

    public String getPresetGeometry() {
        return presetGeometry;
    }

    public void setPresetGeometry(
            String presetGeometry) {

        this.presetGeometry = presetGeometry;
    }

    public String getGeometryAdjustment() {
        return geometryAdjustment;
    }

    public void setGeometryAdjustment(
            String geometryAdjustment) {

        this.geometryAdjustment =
                geometryAdjustment;
    }

    // =========================================================
    // ROTATION
    // =========================================================

    public Integer getRotation() {
        return rotation;
    }

    public void setRotation(Integer rotation) {
        this.rotation = rotation;
    }

    // =========================================================
    // GENERIC DRAWINGML
    // =========================================================

    public List<String> getDrawingXml() {
        return drawingXml;
    }

    public void setDrawingXml(
            List<String> drawingXml) {

        this.drawingXml =
                drawingXml != null
                        ? drawingXml
                        : new ArrayList<>();
    }

    public void addDrawingXml(
            String xml) {

        if (xml != null &&
                !xml.isBlank()) {

            this.drawingXml.add(xml);
        }
    }
}