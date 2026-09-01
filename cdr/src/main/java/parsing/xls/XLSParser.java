package parsing.xls;

import parsing.common.DocumentParser;
import parsing.xlsx.XLSXParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.StructureComponent;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.HyperlinkComponent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class XLSParser implements DocumentParser {

    private XLSParseResult parseResult;


    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        parseResult =
                new XLSParseResult();

        try {

            DocumentModel model =
                    parseUsingHSSF(file);

            XLSExtractionValidator validator =
                    new XLSExtractionValidator();

            boolean valid =
                    validator.validate(
                            parseResult
                    );

            if (valid) {

                parseResult.setParserUsed(
                        "HSSF"
                );

                return model;
            }

            return parseUsingXLSXFallback(file);

        } catch (Exception e) {

            parseResult.setParseSucceeded(
                    false
            );

            parseResult.setExtractionValid(
                    false
            );

            parseResult.setFailureReason(
                    "HSSF parsing failed: "
                    + e.getMessage()
            );

            return parseUsingXLSXFallback(file);
        }
    }


    // =========================================================
    // NATIVE HSSF PARSING
    // =========================================================

    private DocumentModel parseUsingHSSF(
            Path file) throws IOException {

        DocumentModel model =
                new DocumentModel();


        // =====================================================
        // CELLS / TEXT
        // =====================================================

        XLSContentParser contentParser =
                new XLSContentParser();

        List<XLSContentParser.CellData> cells =
                contentParser.parseCells(file);

        parseResult.setCellCount(
                cells.size()
        );

        int index = 1;

        for (XLSContentParser.CellData cell :
                cells) {

            TextComponent text =
                    new TextComponent();

            text.setId(
                    "xls_text_" + index
            );

            text.setText(
                    cell.getValue()
            );

            model.addTextComponent(
                    text
            );

            // Keep old content representation
            model.addContent(
                    cell.getValue()
            );


            StructureComponent structure =
                    new StructureComponent();

            structure.setId(
                    "xls_cell_" + index
            );

            structure.setType(
                    "CELL"
            );

            structure.setName(
                    cell.getSheetName()
                            + "!"
                            + cell.getCellAddress()
            );

            structure.setIndex(
                    index
            );

            model.addStructureComponent(
                    structure
            );

            index++;
        }


        // =====================================================
        // RESOURCES
        // =====================================================

        XLSResourceParser resourceParser =
                new XLSResourceParser();


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

        XLSHyperlinkExtractor hyperlinkExtractor =
                new XLSHyperlinkExtractor();

        List<HyperlinkComponent> hyperlinks =
                hyperlinkExtractor.extract(file);

        for (HyperlinkComponent hyperlink :
                hyperlinks) {

            model.addHyperlinkComponent(
                    hyperlink
            );
        }


        // =====================================================
        // SHEET STRUCTURE
        // =====================================================

        XLSStructureParser structureParser =
                new XLSStructureParser();

        List<StructureComponent> structures =
                structureParser.parse(file);

        parseResult.setSheetCount(
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

        XLSMetadataParser metadataParser =
                new XLSMetadataParser();

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
    // XLS → XLSX FALLBACK
    // =========================================================

    private DocumentModel parseUsingXLSXFallback(
            Path file) throws IOException {

        parseResult.setParserUsed(
                "XLS -> XLSX -> XLSXParser"
        );

        XLSToXLSXConverter converter =
                new XLSToXLSXConverter();

        Path convertedFile =
                converter.convert(file);

        try {

            XLSXParser xlsxParser =
                    new XLSXParser();

            return xlsxParser.parse(
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

    public XLSParseResult getParseResult() {
        return parseResult;
    }
}