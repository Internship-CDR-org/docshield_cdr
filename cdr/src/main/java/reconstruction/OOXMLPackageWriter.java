package reconstruction;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import java.util.ArrayList;
import java.util.List;

import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;


public class OOXMLPackageWriter {

    public void write(
            OOXMLPackage packageData,
            Path outputPath)
            throws IOException {

        if (packageData == null) {

            throw new IllegalArgumentException(
                    "OOXML package cannot be null."
            );
        }


        if (outputPath == null) {

            throw new IllegalArgumentException(
                    "Output path cannot be null."
            );
        }


        Path parent =
                outputPath.getParent();


        if (parent != null) {

            Files.createDirectories(
                    parent
            );
        }


        try (OutputStream outputStream = Files.newOutputStream(outputPath)) {
            writeToStream(packageData, outputStream);
        }
    }


    /** Serializes an OOXML package to memory for nested-package reconstruction. */
    public byte[] writeToBytes(OOXMLPackage packageData) throws IOException {
        if (packageData == null) {
            throw new IllegalArgumentException("OOXML package cannot be null.");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeToStream(packageData, output);
        return output.toByteArray();
    }

    private void writeToStream(OOXMLPackage packageData, OutputStream outputStream) throws IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            for (OOXMLPart part : packageData.getParts()) {
                if (part == null || part.getPartName() == null || part.getPartName().isBlank()) continue;
                String entryName = normalize(part.getPartName());
                byte[] data;
                if ("[Content_Types].xml".equalsIgnoreCase(entryName)) {
                    data = buildContentTypesXml(packageData);
                } else if (isRelationshipPart(entryName)) {
                    data = buildRelationshipXml(packageData, entryName);
                } else {
                    data = part.getData();
                    if (data == null) data = new byte[0];
                }
                zipOutputStream.putNextEntry(new ZipEntry(entryName));
                zipOutputStream.write(data);
                zipOutputStream.closeEntry();
            }
        }
    }


    public void write(
            OOXMLPackage packageData,
            String outputPath)
            throws IOException {

        if (outputPath == null) {

            throw new IllegalArgumentException(
                    "Output path cannot be null."
            );
        }


        write(
                packageData,
                Path.of(outputPath)
        );
    }


    private byte[] buildContentTypesXml(OOXMLPackage packageData) {

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");

        for (var entry : packageData.getContentTypes().entrySet()) {
            String name = entry.getKey();
            String contentType = entry.getValue();
            if (name == null || name.isBlank() || contentType == null || contentType.isBlank()) continue;

            if (name.startsWith(".")) {
                xml.append("<Default Extension=\"")
                        .append(escapeXmlAttribute(name.substring(1)))
                        .append("\" ContentType=\"")
                        .append(escapeXmlAttribute(contentType))
                        .append("\"/>");
            } else {
                String partName = name.startsWith("/") ? name : "/" + name;
                xml.append("<Override PartName=\"")
                        .append(escapeXmlAttribute(partName))
                        .append("\" ContentType=\"")
                        .append(escapeXmlAttribute(contentType))
                        .append("\"/>");
            }
        }

        xml.append("</Types>");
        return xml.toString().getBytes(StandardCharsets.UTF_8);
    }


    private byte[] buildRelationshipXml(
            OOXMLPackage packageData,
            String relationshipPartName) {

        String sourcePart =
                getSourcePartFromRelationshipPart(
                        relationshipPartName
                );


        List<OOXMLRelationship> relationships =
                new ArrayList<>(
                        packageData.getRelationshipsFrom(
                                sourcePart
                        )
                );


        StringBuilder xml =
                new StringBuilder();


        xml.append(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        );

        xml.append(
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        );


        for (OOXMLRelationship relationship :
                relationships) {

            if (relationship == null) {
                continue;
            }


            String id =
                    relationship.getId();

            String type =
                    relationship.getType();

            String target =
                    relationship.getTarget();


            if (id == null ||
                    id.isBlank() ||
                    type == null ||
                    type.isBlank() ||
                    target == null ||
                    target.isBlank()) {

                continue;
            }


            xml.append(
                    "<Relationship"
            );


            xml.append(
                    " Id=\""
            );

            xml.append(
                    escapeXmlAttribute(id)
            );

            xml.append(
                    "\""
            );


            xml.append(
                    " Type=\""
            );

            xml.append(
                    escapeXmlAttribute(type)
            );

            xml.append(
                    "\""
            );


            xml.append(
                    " Target=\""
            );

            xml.append(
                    escapeXmlAttribute(target)
            );

            xml.append(
                    "\""
            );


            String targetMode =
                    relationship.getTargetMode();


            if (targetMode != null &&
                    !targetMode.isBlank()) {

                xml.append(
                        " TargetMode=\""
                );

                xml.append(
                        escapeXmlAttribute(
                                targetMode
                        )
                );

                xml.append(
                        "\""
                );
            }


            xml.append(
                    "/>"
            );
        }


        xml.append(
                "</Relationships>"
        );


        return xml
                .toString()
                .getBytes(
                        StandardCharsets.UTF_8
                );
    }


    private String getSourcePartFromRelationshipPart(
            String relationshipPartName) {

        String normalized =
                normalize(
                        relationshipPartName
                );


        if ("_rels/.rels".equals(
                normalized
        )) {

            return null;
        }


        int relsIndex =
                normalized.lastIndexOf(
                        "/_rels/"
                );


        if (relsIndex < 0) {
            return null;
        }


        String directory =
                normalized.substring(
                        0,
                        relsIndex
                );


        String fileName =
                normalized.substring(
                        relsIndex +
                        "/_rels/".length()
                );


        if (!fileName.endsWith(
                ".rels"
        )) {

            return null;
        }


        fileName =
                fileName.substring(
                        0,
                        fileName.length() -
                        ".rels".length()
                );


        if (directory.isBlank()) {
            return fileName;
        }


        return directory +
                "/" +
                fileName;
    }


    private boolean isRelationshipPart(
            String partName) {

        return partName != null &&
                (
                        "_rels/.rels".equals(
                                partName
                        )
                        ||
                        (
                                partName.contains(
                                        "/_rels/"
                                )
                                &&
                                partName.endsWith(
                                        ".rels"
                                )
                        )
                );
    }


    private String normalize(
            String value) {

        if (value == null) {
            return null;
        }

        return value
                .trim()
                .replace('\\', '/')
                .replaceFirst(
                        "^/+",
                        ""
                );
    }


    private String escapeXmlAttribute(
            String value) {

        if (value == null) {
            return "";
        }


        return value
                .replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("'", "&apos;");
    }
}