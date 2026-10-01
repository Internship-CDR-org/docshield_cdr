package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.HyperlinkComponent;
import model.common.ThreatComponent;
import model.common.StructureComponent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class PDFParser implements DocumentParser {

    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        DocumentModel model =
                new DocumentModel();


        // =========================================================
        // TEXT CONTENT
        // =========================================================

        PDFContentParser contentParser =
                new PDFContentParser();

        PDFFormParser formParser =
                new PDFFormParser();


        // ---------------------------------------------------------
        // Legacy text representation
        // ---------------------------------------------------------

        List<String> text =
                contentParser.parseText(file);

        for (String value : text) {

            model.addContent(value);
        }


        // ---------------------------------------------------------
        // Common IR text representation
        // ---------------------------------------------------------

        List<TextComponent> textComponents =
                contentParser.parseTextComponents(file);

        for (TextComponent component :
                textComponents) {

            model.addTextComponent(
                    component
            );
        }


        // =========================================================
        // METADATA
        // =========================================================

        PDFMetadataParser metadataParser =
                new PDFMetadataParser();

        Map<String, String> metadata =
                metadataParser.parse(file);

        for (Map.Entry<String, String> entry :
                metadata.entrySet()) {

            if (entry.getValue() != null
                    && !entry.getValue().isBlank()) {

                model.getMetadata()
                        .addCoreMetadata(
                                entry.getKey(),
                                entry.getValue()
                        );
            }
        }


        // =========================================================
        // PDF FORM STRUCTURE
        // =========================================================

        List<StructureComponent> formComponents =
                formParser.parseStructureComponents(file);

        for (StructureComponent component :
                formComponents) {

            model.addStructureComponent(
                    component
            );
        }


        // =========================================================
        // IMAGES
        // =========================================================

        PDFResourceParser resourceParser =
                new PDFResourceParser();

        List<ImageComponent> images =
                resourceParser.parseImageComponents(file);

        for (ImageComponent image :
                images) {

            model.addImageComponent(
                    image
            );
        }


        // =========================================================
        // INTERACTIVE CONTENT
        // =========================================================

        PDFInteractiveParser interactiveParser =
                new PDFInteractiveParser();


        // ---------------------------------------------------------
        // Hyperlinks
        // ---------------------------------------------------------

        List<HyperlinkComponent> hyperlinks =
                interactiveParser
                        .parseHyperlinkComponents(file);

        for (HyperlinkComponent hyperlink :
                hyperlinks) {

            model.addHyperlinkComponent(
                    hyperlink
            );
        }


        // ---------------------------------------------------------
        // Threats
        // ---------------------------------------------------------

        List<ThreatComponent> interactiveThreats =
                interactiveParser
                        .parseThreatComponents(file);

        for (ThreatComponent threat :
                interactiveThreats) {

            model.addThreatComponent(
                    threat
            );
        }


        // =========================================================
        // EMBEDDED FILES
        // =========================================================

        PDFEmbeddedParser embeddedParser =
                new PDFEmbeddedParser();

        List<EmbeddedObjectComponent> embeddedObjects =
                embeddedParser
                        .parseEmbeddedObjectComponents(file);

        for (EmbeddedObjectComponent object :
                embeddedObjects) {

            model.addEmbeddedObjectComponent(
                    object
            );
        }


        // =========================================================
        // PDF DOCUMENT / PAGE STRUCTURE
        // =========================================================

        PDFStructureParser structureParser =
                new PDFStructureParser();

        List<StructureComponent> structureComponents =
                structureParser
                        .parseStructureComponents(file);

        for (StructureComponent component :
                structureComponents) {

            model.addStructureComponent(
                    component
            );
        }


        // =========================================================
        // RETURN COMMON IR
        // =========================================================

        return model;
    }
}