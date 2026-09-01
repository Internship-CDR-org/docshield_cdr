package parsing.doc;

import parsing.common.DocumentParser;
import parsing.docx.DOCXParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.ImageComponent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class DOCParser implements DocumentParser {

    private DOCParseResult parseResult;

    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        parseResult = new DOCParseResult();

        // =====================================================
        // 1. TRY NATIVE HWPF PARSING
        // =====================================================

        try {

            DocumentModel model =
                    parseUsingHWPF(file);

            DOCExtractionValidator validator =
                    new DOCExtractionValidator();

            boolean valid =
                    validator.validate(parseResult);

            // -------------------------------------------------
            // HWPF extraction is acceptable
            // -------------------------------------------------

            if (valid) {
                return model;
            }

            // -------------------------------------------------
            // HWPF completed but extraction is suspicious
            // -------------------------------------------------

            return parseUsingDOCXFallback(file);

        } catch (Exception e) {

            // -------------------------------------------------
            // HWPF itself failed
            // -------------------------------------------------

            parseResult.setParseSucceeded(false);
            parseResult.setExtractionValid(false);

            parseResult.setFailureReason(
                    "HWPF parsing failed: "
                    + e.getMessage()
            );

            // -------------------------------------------------
            // Try DOC → DOCX fallback
            // -------------------------------------------------

            return parseUsingDOCXFallback(file);
        }
    }


    // =========================================================
    // HWPF PARSING
    // =========================================================

    private DocumentModel parseUsingHWPF(Path file)
            throws IOException {

        DocumentModel model =
                new DocumentModel();

        // =====================================================
        // TEXT
        // =====================================================

        DOCContentParser contentParser =
                new DOCContentParser();

        List<String> text =
                contentParser.parseText(file);

        parseResult.setTextCount(
                text.size()
        );

        int paragraphCount = 0;

        for (String value : text) {

            if (value != null &&
                    !value.isBlank()) {

                String[] paragraphs =
                        value.split("\\r?\\n");

                for (String paragraph :
                        paragraphs) {

                    if (!paragraph.isBlank()) {
                        paragraphCount++;
                    }
                }
            }
        }

        parseResult.setParagraphCount(
                paragraphCount
        );


        // =====================================================
        // ADD TEXT TO MODEL
        // =====================================================

        for (String value : text) {

            model.addContent(value);

            TextComponent component =
                    new TextComponent();

            component.setId(
                    "text_" +
                    model.getTextComponents().size()
            );

            component.setText(value);

            model.addTextComponent(component);
        }


        // =====================================================
        // METADATA
        // =====================================================

        DOCMetadataParser metadataParser =
                new DOCMetadataParser();

        Map<String, String> metadata =
                metadataParser.parse(file);

        for (Map.Entry<String, String> entry :
                metadata.entrySet()) {

            model.getMetadata()
                    .addCoreMetadata(
                            entry.getKey(),
                            entry.getValue()
                    );
        }


        // =====================================================
        // RESOURCES
        // =====================================================

        DOCResourceParser resourceParser =
                new DOCResourceParser();


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

            model.addImageComponent(image);
        }


        // -----------------------------------------------------
        // EMBEDDED OBJECTS
        // -----------------------------------------------------

        List<String> objects =
                resourceParser
                        .parseEmbeddedObjects(file);

        parseResult.setEmbeddedObjectCount(
                objects.size()
        );

        for (String object :
                objects) {

            model.addEmbeddedObject(object);
        }


        // =====================================================
        // HWPF PARSING SUCCESSFUL
        // =====================================================

        parseResult.setParseSucceeded(true);

        /*
         * Do NOT mark extractionValid here.
         *
         * The validator decides whether the extraction
         * is trustworthy.
         */

        parseResult.setExtractionValid(false);

        return model;
    }


    // =========================================================
    // DOC → DOCX FALLBACK
    // =========================================================

    private DocumentModel parseUsingDOCXFallback(
            Path file) throws IOException {

        parseResult.setParserUsed(
                "DOC -> DOCX -> DOCXParser"
        );

        DOCToDOCXConverter converter =
                new DOCToDOCXConverter();

        Path convertedFile =
                converter.convert(file);

        try {

            DOCXParser docxParser =
                    new DOCXParser();

            return docxParser.parse(
                    convertedFile
            );

        } finally {

            // -------------------------------------------------
            // Remove temporary converted DOCX
            // -------------------------------------------------

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
                // invalidate the reconstructed model.
            }
        }
    }


    // =========================================================
    // PARSE RESULT
    // =========================================================

    public DOCParseResult getParseResult() {
        return parseResult;
    }
}