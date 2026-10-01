package parsing.pptx;

import parsing.common.DocumentParser;
import parsing.common.CoreMetadataParser;
import parsing.common.AppMetadataParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.ImageComponent;
import model.common.StructureComponent;
import model.pptx.PPTXTheme;
import model.pptx.PPTXLayout;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class PPTXParser implements DocumentParser {

    // =========================================================
    // PPTX PARSERS
    // =========================================================

    private final PPTXLayoutParser layoutParser =
            new PPTXLayoutParser();

    private final PPTXSlideLayoutParser slideLayoutParser =
            new PPTXSlideLayoutParser();


    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        DocumentModel model =
                new DocumentModel();


        // =========================================================
        // TEXT
        // =========================================================

        PPTXContentParser contentParser =
                new PPTXContentParser();

        List<TextComponent> textComponents =
                contentParser.parseTextComponents(file);

        for (TextComponent component :
                textComponents) {

            model.addTextComponent(
                    component
            );

            // Keep existing representation
            model.addContent(
                    component.getText()
            );
        }


        // =========================================================
        // RESOURCES
        // =========================================================

        PPTXResourceParser resourceParser =
                new PPTXResourceParser();


        // =========================================================
        // IMAGES
        // =========================================================

        List<ImageComponent> imageComponents =
                resourceParser.parseImageComponents(file);

        for (ImageComponent image :
                imageComponents) {

            model.addImageComponent(
                    image
            );
        }


        // =========================================================
        // EMBEDDED OBJECTS
        // =========================================================

        for (String object :
                resourceParser.parseEmbeddedObjects(file)) {

            model.addEmbeddedObject(
                    object
            );
        }


        // =========================================================
        // CORE METADATA
        // =========================================================

        CoreMetadataParser coreMetadataParser =
                new CoreMetadataParser();

        Map<String, String> coreMetadata =
                coreMetadataParser.parse(file);

        for (Map.Entry<String, String> entry :
                coreMetadata.entrySet()) {

            if (entry.getValue() != null &&
                    !entry.getValue().isBlank()) {

                model.getMetadata()
                        .addCoreMetadata(
                                entry.getKey(),
                                entry.getValue()
                        );
            }
        }


        // =========================================================
        // APPLICATION METADATA
        // =========================================================

        AppMetadataParser appMetadataParser =
                new AppMetadataParser();

        Map<String, String> appMetadata =
                appMetadataParser.parse(file);

        for (Map.Entry<String, String> entry :
                appMetadata.entrySet()) {

            if (entry.getValue() != null &&
                    !entry.getValue().isBlank()) {

                model.getMetadata()
                        .addApplicationMetadata(
                                entry.getKey(),
                                entry.getValue()
                        );
            }
        }


        // =========================================================
        // THEME
        // =========================================================

        PPTXThemeParser themeParser =
                new PPTXThemeParser();

        PPTXTheme theme =
                themeParser.parse(file);

        model.setPptxTheme(
                theme
        );


        // =========================================================
        // STRUCTURE
        // =========================================================

        PPTXStructureParser structureParser =
                new PPTXStructureParser();

        List<StructureComponent> structureComponents =
                structureParser.parseStructureComponents(file);

        for (StructureComponent component :
                structureComponents) {

            model.addStructureComponent(
                    component
            );
        }


        // =========================================================
        // PPTX LAYOUTS
        // =========================================================

        List<PPTXLayout> layouts =
                layoutParser.parse(file);

        for (PPTXLayout layout :
                layouts) {

            model.addPptxLayout(
                    layout
            );
        }


        // =========================================================
        // SLIDE → LAYOUT MAPPING
        // =========================================================

        List<Integer> slideLayoutIndices =
                slideLayoutParser.parse(file);

        for (Integer layoutIndex :
                slideLayoutIndices) {

            model.addPptxSlideLayoutIndex(
                    layoutIndex
            );
        }


        // =========================================================
        // RETURN COMMON IR
        // =========================================================


        return model;
    }
}