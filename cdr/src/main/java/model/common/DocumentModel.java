package model.common;

import identification.FileInfo;
import model.pptx.PPTXLayout;
import model.pptx.PPTXTheme;

import java.util.ArrayList;
import java.util.List;

public class DocumentModel {

    private FileInfo fileInfo;


    // =========================================================
    // EXISTING REPORT-ORIENTED DATA
    // Keep these temporarily for backward compatibility.
    // =========================================================

    private MetadataModel metadata;

    private List<String> content;
    private List<String> structure;
    private List<String> relationships;
    private List<String> threats;
    private List<String> images;
    private List<String> embeddedObjects;

    private List<PPTXLayout> pptxLayouts;

    // Maps slide number → layout index
    private List<Integer> pptxSlideLayoutIndices;


    // =========================================================
    // NEW INTERMEDIATE REPRESENTATION (IR)
    // These will be used for reconstruction.
    // =========================================================

    private List<TextComponent> textComponents;
    private List<ImageComponent> imageComponents;
    private List<HyperlinkComponent> hyperlinkComponents;
    private List<StructureComponent> structureComponents;
    private List<EmbeddedObjectComponent> embeddedObjectComponents;
    private List<ThreatComponent> threatComponents;

    private PPTXTheme pptxTheme;


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public DocumentModel() {

        // Existing model
        metadata = new MetadataModel();

        content = new ArrayList<>();
        structure = new ArrayList<>();
        relationships = new ArrayList<>();
        threats = new ArrayList<>();
        images = new ArrayList<>();
        embeddedObjects = new ArrayList<>();

        pptxLayouts = new ArrayList<>();

        pptxSlideLayoutIndices =
                new ArrayList<>();


        // New IR
        textComponents = new ArrayList<>();
        imageComponents = new ArrayList<>();
        hyperlinkComponents = new ArrayList<>();
        structureComponents = new ArrayList<>();
        embeddedObjectComponents = new ArrayList<>();
        threatComponents = new ArrayList<>();

        pptxTheme = new PPTXTheme();
    }


    // =========================================================
    // EXISTING METHODS
    // =========================================================

    public MetadataModel getMetadata() {
        return metadata;
    }

    public List<String> getContent() {
        return content;
    }

    public List<String> getStructure() {
        return structure;
    }

    public List<String> getRelationships() {
        return relationships;
    }

    public List<String> getThreats() {
        return threats;
    }

    public List<String> getImages() {
        return images;
    }

    public List<String> getEmbeddedObjects() {
        return embeddedObjects;
    }


    public void addContent(String value) {
        content.add(value);
    }

    public void addStructure(String value) {
        structure.add(value);
    }

    public void addRelationship(String value) {
        relationships.add(value);
    }

    public void addThreat(String value) {
        threats.add(value);
    }

    public void addImage(String value) {
        images.add(value);
    }

    public void addEmbeddedObject(String value) {
        embeddedObjects.add(value);
    }


    // =========================================================
    // NEW IR METHODS
    // =========================================================

    public List<TextComponent> getTextComponents() {
        return textComponents;
    }

    public List<ImageComponent> getImageComponents() {
        return imageComponents;
    }

    public List<HyperlinkComponent> getHyperlinkComponents() {
        return hyperlinkComponents;
    }

    public List<StructureComponent> getStructureComponents() {
        return structureComponents;
    }

    public List<EmbeddedObjectComponent>
    getEmbeddedObjectComponents() {

        return embeddedObjectComponents;
    }

    public List<ThreatComponent> getThreatComponents() {
        return threatComponents;
    }

    public PPTXTheme getPptxTheme() {
        return pptxTheme;
    }


    // =========================================================
    // ADD COMPONENTS TO IR
    // =========================================================

    public void addTextComponent(
            TextComponent component) {

        textComponents.add(component);
    }

    public void addImageComponent(
            ImageComponent component) {

        imageComponents.add(component);
    }

    public void addHyperlinkComponent(
            HyperlinkComponent component) {

        hyperlinkComponents.add(component);
    }

    public void addStructureComponent(
            StructureComponent component) {

        structureComponents.add(component);
    }

    public void addEmbeddedObjectComponent(
            EmbeddedObjectComponent component) {

        embeddedObjectComponents.add(component);
    }

    public void addThreatComponent(
            ThreatComponent component) {

        threatComponents.add(component);
    }


    // =========================================================
    // FILE INFORMATION
    // =========================================================

    public FileInfo getFileInfo() {
        return fileInfo;
    }

    public void setFileInfo(
            FileInfo fileInfo) {

        this.fileInfo = fileInfo;
    }


    // =========================================================
    // PPTX THEME
    // =========================================================

    public void setPptxTheme(
            PPTXTheme pptxTheme) {

        this.pptxTheme = pptxTheme;
    }


    // =========================================================
    // PPTX LAYOUTS
    // =========================================================

    public List<PPTXLayout> getPptxLayouts() {
        return pptxLayouts;
    }

    public void addPptxLayout(
            PPTXLayout layout) {

        pptxLayouts.add(layout);
    }


    // =========================================================
    // PPTX SLIDE → LAYOUT MAPPING
    // =========================================================

    public List<Integer>
    getPptxSlideLayoutIndices() {

        return pptxSlideLayoutIndices;
    }

    public void addPptxSlideLayoutIndex(
            int layoutIndex) {

        pptxSlideLayoutIndices.add(
                layoutIndex
        );
    }
}