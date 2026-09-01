package parsing.ppt;

import parsing.common.DocumentParser;
import parsing.pptx.PPTXParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.HyperlinkComponent;
import model.common.StructureComponent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class PPTParser implements DocumentParser {

    private PPTParseResult parseResult;


    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        parseResult =
                new PPTParseResult();

        try {

            DocumentModel model =
                    parseUsingHSLF(file);

            PPTExtractionValidator validator =
                    new PPTExtractionValidator();

            boolean valid =
                    validator.validate(parseResult);

            if (valid) {

                parseResult.setParserUsed(
                        "HSLF"
                );

                return model;
            }

            return parseUsingPPTXFallback(file);

        } catch (Exception e) {

            parseResult.setParseSucceeded(
                    false
            );

            parseResult.setExtractionValid(
                    false
            );

            parseResult.setFailureReason(
                    "HSLF parsing failed: "
                    + e.getMessage()
            );

            return parseUsingPPTXFallback(file);
        }
    }


    // =========================================================
    // NATIVE HSLF PARSING
    // =========================================================

    private DocumentModel parseUsingHSLF(
            Path file) throws IOException {

        DocumentModel model =
                new DocumentModel();


        // =====================================================
        // TEXT
        // =====================================================

        PPTContentParser contentParser =
                new PPTContentParser();

        List<String> content =
                contentParser.parseText(file);

        parseResult.setTextCount(
                content.size()
        );

        int textNumber = 1;

        for (String value :
                content) {

            model.addContent(value);

            TextComponent component =
                    new TextComponent();

            component.setId(
                    "ppt_text_" +
                    textNumber
            );

            component.setText(value);

            model.addTextComponent(
                    component
            );

            textNumber++;
        }


        // =====================================================
        // RESOURCES
        // =====================================================

        PPTResourceParser resourceParser =
                new PPTResourceParser();


        // -----------------------------------------------------
        // IMAGES
        // -----------------------------------------------------

        List<ImageComponent> images =
                resourceParser
                        .parseImageComponents(file);

        parseResult.setImageCount(
                images.size()
        );

        for (ImageComponent image :
                images) {

            model.addImageComponent(
                    image
            );
        }


        // -----------------------------------------------------
        // EMBEDDED OBJECTS
        // -----------------------------------------------------

        List<EmbeddedObjectComponent> objects =
                resourceParser
                        .parseEmbeddedObjectComponents(
                                file
                        );

        parseResult.setEmbeddedObjectCount(
                objects.size()
        );

        for (EmbeddedObjectComponent object :
                objects) {

            model.addEmbeddedObjectComponent(
                    object
            );
        }


        // =====================================================
        // HYPERLINKS
        // =====================================================

        PPTHyperlinkExtractor hyperlinkExtractor =
                new PPTHyperlinkExtractor();

        List<HyperlinkComponent> hyperlinks =
                hyperlinkExtractor.extract(file);

        for (HyperlinkComponent hyperlink :
                hyperlinks) {

            model.addHyperlinkComponent(
                    hyperlink
            );
        }


        // =====================================================
        // STRUCTURE
        // =====================================================

        PPTStructureParser structureParser =
                new PPTStructureParser();

        List<StructureComponent> structures =
                structureParser.parse(file);

        parseResult.setSlideCount(
                structures.size()
        );

        for (StructureComponent structure :
                structures) {

            model.addStructureComponent(
                    structure
            );
        }


        // =====================================================
        // METADATA
        // =====================================================

        PPTMetadataParser metadataParser =
                new PPTMetadataParser();

        Map<String, String> metadata =
                metadataParser
                        .parseCoreMetadata(file);

        for (Map.Entry<String, String> entry :
                metadata.entrySet()) {

            model.getMetadata()
                    .addCoreMetadata(
                            entry.getKey(),
                            entry.getValue()
                    );
        }


        // =====================================================
        // PARSING SUCCESS
        // =====================================================

        parseResult.setParseSucceeded(
                true
        );

        return model;
    }


    // =========================================================
    // PPT → PPTX FALLBACK
    // =========================================================

    private DocumentModel parseUsingPPTXFallback(
            Path file) throws IOException {

        parseResult.setParserUsed(
                "PPT -> PPTX -> PPTXParser"
        );

        PPTToPPTXConverter converter =
                new PPTToPPTXConverter();

        Path convertedFile =
                converter.convert(file);

        try {

            PPTXParser pptxParser =
                    new PPTXParser();

            return pptxParser.parse(
                    convertedFile
            );

        } finally {

            try {

                Files.deleteIfExists(
                        convertedFile
                );

                Path temporaryDirectory =
                        convertedFile.getParent();

                if (temporaryDirectory != null) {

                    Files.deleteIfExists(
                            temporaryDirectory
                    );
                }

            } catch (IOException ignored) {
                // Cleanup failure should not
                // invalidate the parsed model.
            }
        }
    }


    // =========================================================
    // PARSE RESULT
    // =========================================================

    public PPTParseResult getParseResult() {
        return parseResult;
    }
}