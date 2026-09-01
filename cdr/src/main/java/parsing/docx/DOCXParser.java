package parsing.docx;

import parsing.common.DocumentParser;
import parsing.common.CoreMetadataParser;
import parsing.common.AppMetadataParser;

import model.common.DocumentModel;
import model.common.ComponentCategory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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
                        break;

                    case RELATIONSHIP:
                        model.addRelationship(name);
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