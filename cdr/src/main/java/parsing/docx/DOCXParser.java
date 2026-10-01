package parsing.docx;

import parsing.common.DocumentParser;
import parsing.common.CoreMetadataParser;
import parsing.common.AppMetadataParser;

import model.common.DocumentModel;
import model.common.ComponentCategory;
import model.common.TextComponent;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.StructureComponent;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.io.InputStream;
import java.net.URLConnection;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;

public class DOCXParser implements DocumentParser {

    @Override
    public DocumentModel parse(Path file) throws IOException {

        DocumentModel model = new DocumentModel();

        DOCXResourceParser resourceParser = new DOCXResourceParser();

        for (String image :
                resourceParser.parseImages(file)) {

            model.addImage(image);
        }

        for (String object :
                resourceParser.parseEmbeddedObjects(file)) {

            model.addEmbeddedObject(object);
        }

        DOCXContentParser contentParser =
                new DOCXContentParser();

        java.util.List<String> text =
                contentParser.parseText(file);

        for (String value : text) {
            model.addContent(value);
        }

        // Populate the common IR used by ReportWriter.
        for (TextComponent component :
                contentParser.parseTextComponents(file)) {
            model.addTextComponent(component);
        }

        // Populate image components with the actual package bytes.
        try (ZipFile zipFile = new ZipFile(file.toFile())) {
            int imageIndex = 0;
            for (String imageName : resourceParser.parseImages(file)) {
                ZipEntry entry = zipFile.getEntry(imageName);
                if (entry == null) {
                    continue;
                }
                byte[] data;
                try (InputStream input = zipFile.getInputStream(entry)) {
                    data = input.readAllBytes();
                }
                ImageComponent image = new ImageComponent();
                image.setId("image_" + imageIndex++);
                image.setFileName(imageName);
                image.setMimeType(URLConnection.guessContentTypeFromName(imageName));
                image.setData(data);

                try (ByteArrayInputStream imageInput =
                             new ByteArrayInputStream(data)) {
                    BufferedImage decoded = ImageIO.read(imageInput);
                    if (decoded != null) {
                        image.setWidth(decoded.getWidth());
                        image.setHeight(decoded.getHeight());
                    }
                }

                model.addImageComponent(image);
            }

            int objectIndex = 0;
            for (String objectName : resourceParser.parseEmbeddedObjects(file)) {
                ZipEntry entry = zipFile.getEntry(objectName);
                if (entry == null) {
                    continue;
                }
                byte[] data;
                try (InputStream input = zipFile.getInputStream(entry)) {
                    data = input.readAllBytes();
                }
                EmbeddedObjectComponent object = new EmbeddedObjectComponent();
                object.setId("embedded_" + objectIndex++);
                object.setName(objectName);
                object.setType(URLConnection.guessContentTypeFromName(objectName));
                object.setData(data);
                model.addEmbeddedObjectComponent(object);
            }
        }

        try (ZipFile zipFile = new ZipFile(file.toFile())) {

            Enumeration<? extends ZipEntry> entries =
                    zipFile.entries();

            while (entries.hasMoreElements()) {

                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                if (entry.isDirectory()) {
                    continue;
                }

                ComponentCategory type =
                        classify(name);

                if (type == null) {
                    continue;
                }

                switch (type) {

                    case METADATA:
                        break;

                    case CONTENT:
                        break;

                    case STRUCTURE:
                        model.addStructure(name);
                        StructureComponent structure =
                                new StructureComponent(
                                        "structure_" + model.getStructureComponents().size(),
                                        "DOCX_STRUCTURE",
                                        name,
                                        model.getStructureComponents().size()
                                );
                        model.addStructureComponent(structure);
                        break;

                    case RELATIONSHIP:
                        model.addRelationship(name);
                        StructureComponent relationship =
                                new StructureComponent(
                                        "relationship_" + model.getStructureComponents().size(),
                                        "DOCX_RELATIONSHIP",
                                        name,
                                        model.getStructureComponents().size()
                                );
                        model.addStructureComponent(relationship);
                        break;

                    default:
                        break;
                }
            }
        }

        CoreMetadataParser coreParser =
                new CoreMetadataParser();

        java.util.Map<String, String> coreMetadata =
                coreParser.parse(file);

        for (java.util.Map.Entry<String, String> entry
                : coreMetadata.entrySet()) {

            model.getMetadata().addCoreMetadata(
                    entry.getKey(),
                    entry.getValue()
            );
        }

        AppMetadataParser appParser =
                new AppMetadataParser();

        java.util.Map<String, String> appMetadata =
                appParser.parse(file);

        for (java.util.Map.Entry<String, String> entry
                : appMetadata.entrySet()) {

            model.getMetadata().addApplicationMetadata(
                    entry.getKey(),
                    entry.getValue()
            );
        }

        return model;
    }

    private ComponentCategory classify(String name) {

        if (name.startsWith("docProps/")) {
            return ComponentCategory.METADATA;
        }

        if (name.equals("word/document.xml")
                || name.equals("word/footnotes.xml")
                || name.equals("word/endnotes.xml")
                || name.equals("word/comments.xml")) {
            return ComponentCategory.CONTENT;
        }

        if (name.contains("_rels/") || name.endsWith(".rels")) {
            return ComponentCategory.RELATIONSHIP;
        }

        if (name.equals("word/styles.xml")
                || name.equals("word/numbering.xml")
                || name.equals("word/settings.xml")
                || name.equals("word/fontTable.xml")) {
            return ComponentCategory.STRUCTURE;
        }
        
        return null;
    }
}