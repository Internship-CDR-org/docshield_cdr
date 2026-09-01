package parsing.rtf;

import parsing.common.DocumentParser;

import model.common.DocumentModel;
import model.common.TextComponent;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.HyperlinkComponent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class RTFParser implements DocumentParser {

    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        DocumentModel model =
                new DocumentModel();

        RTFContentParser contentParser =
                new RTFContentParser();

        RTFResourceParser resourceParser =
                new RTFResourceParser();


        // =====================================================
        // TEXT
        // =====================================================

        List<String> text =
                contentParser.parseText(file);

        int textNumber = 1;

        for (String value : text) {

            model.addContent(value);

            TextComponent component =
                    new TextComponent();

            component.setId(
                    "rtf_text_" +
                    textNumber
            );

            component.setText(value);

            model.addTextComponent(
                    component
            );

            textNumber++;
        }


        // =====================================================
        // IMAGES
        // =====================================================

        List<ImageComponent> images =
                resourceParser.parseImageComponents(file);

        for (ImageComponent image :
                        images) {

                model.addImageComponent(image);
                }

                List<EmbeddedObjectComponent> objects =
                resourceParser.parseEmbeddedObjectComponents(file);

        for (EmbeddedObjectComponent object :
                objects) {

        model.addEmbeddedObjectComponent(object);
        }

        RTFHyperlinkExtractor hyperlinkExtractor =
                new RTFHyperlinkExtractor();

        List<HyperlinkComponent> hyperlinks =
                hyperlinkExtractor.extract(file);

        for (HyperlinkComponent hyperlink :
                hyperlinks) {

        model.addHyperlinkComponent(
                hyperlink
        );
        }

        RTFMetadataParser metadataParser =
                new RTFMetadataParser();

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


        return model;
    }
}