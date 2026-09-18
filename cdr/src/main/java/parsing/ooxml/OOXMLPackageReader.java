package parsing.ooxml;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.nio.file.Files;
import java.nio.file.Path;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;


public class OOXMLPackageReader {

    private static final String RELATIONSHIP_NAMESPACE =
            "http://schemas.openxmlformats.org/package/2006/relationships";

    private static final String CONTENT_TYPES_NAMESPACE =
            "http://schemas.openxmlformats.org/package/2006/content-types";


    private static final int MAX_ZIP_ENTRIES = 10000;
    private static final long MAX_TOTAL_UNCOMPRESSED_BYTES = 256L * 1024L * 1024L;
    private static final long MAX_SINGLE_PART_BYTES = 128L * 1024L * 1024L;


    public OOXMLPackage read(
            Path inputFile)
            throws IOException {

        if (inputFile == null) {

            throw new IllegalArgumentException(
                    "Input file cannot be null."
            );
        }


        if (!Files.exists(inputFile)) {

            throw new IOException(
                    "Input file does not exist: " +
                    inputFile
            );
        }


        if (!Files.isRegularFile(inputFile)) {

            throw new IOException(
                    "Input path is not a regular file: " +
                    inputFile
            );
        }


        OOXMLPackage packageData =
                new OOXMLPackage();


        try (
                ZipFile zipFile =
                        new ZipFile(
                                inputFile.toFile()
                        )
        ) {

            readParts(
                    zipFile,
                    packageData
            );
        }


        readContentTypes(
                packageData
        );

        validateXmlParts(packageData);

        readRelationships(
                packageData
        );


        return packageData;
    }


    /**
     * Reads an OOXML/OPC package from an input stream. This overload is used
     * for nested embedded OOXML packages so they can be inspected without
     * materializing untrusted embedded data to disk. The stream is consumed
     * but is not closed by this method.
     */
    public OOXMLPackage read(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new IllegalArgumentException("Input stream cannot be null.");
        }

        OOXMLPackage packageData = new OOXMLPackage();
        readParts(inputStream, packageData);
        readContentTypes(packageData);
        validateXmlParts(packageData);
        readRelationships(packageData);
        return packageData;
    }

    /** Reads an OOXML/OPC package from an in-memory byte array. */
    public OOXMLPackage read(byte[] data) throws IOException {
        if (data == null) {
            throw new IllegalArgumentException("Package data cannot be null.");
        }
        return read(new ByteArrayInputStream(data));
    }


    public OOXMLPackage read(
            String inputFile)
            throws IOException {

        if (inputFile == null) {

            throw new IllegalArgumentException(
                    "Input file cannot be null."
            );
        }

        return read(
                Path.of(inputFile)
        );
    }


    private void readParts(
            InputStream inputStream,
            OOXMLPackage packageData) throws IOException {

        try (ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
            java.util.HashSet<String> seenNames = new java.util.HashSet<>();
            int entryCount = 0;
            long totalBytes = 0L;

            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                if (++entryCount > MAX_ZIP_ENTRIES) {
                    throw new IOException("OOXML package contains too many ZIP entries.");
                }
                if (entry.isDirectory()) {
                    continue;
                }

                String rawName = entry.getName();
                security.sandbox.PathSandbox.assertSafeZipEntry(rawName);
                if (rawName == null || rawName.isBlank()) {
                    throw new IOException("OOXML package contains an empty ZIP entry name.");
                }
                if (rawName.startsWith("/") || rawName.startsWith("\\") || containsTraversal(rawName)) {
                    throw new IOException("Unsafe OOXML ZIP entry path: " + rawName);
                }

                String partName = normalize(rawName);
                if (!seenNames.add(partName)) {
                    throw new IOException("Duplicate OOXML ZIP entry: " + partName);
                }

                byte[] data = readPartData(zipInputStream, partName, totalBytes);
                totalBytes += data.length;
                packageData.addPart(new OOXMLPart(partName, null, data));
            }
        }
    }


    private void readParts(
            ZipFile zipFile,
            OOXMLPackage packageData)
            throws IOException {

        Enumeration<? extends ZipEntry> entries =
                zipFile.entries();

        java.util.HashSet<String> seenNames = new java.util.HashSet<>();
        int entryCount = 0;
        long totalBytes = 0L;

        while (entries.hasMoreElements()) {

            ZipEntry entry =
                    entries.nextElement();

            if (++entryCount > MAX_ZIP_ENTRIES) {
                throw new IOException("OOXML package contains too many ZIP entries.");
            }


            if (entry.isDirectory()) {
                continue;
            }


            String rawName = entry.getName();
            security.sandbox.PathSandbox.assertSafeZipEntry(rawName);
            if (rawName == null || rawName.isBlank()) {
                throw new IOException("OOXML package contains an empty ZIP entry name.");
            }

            if (rawName.startsWith("/") || rawName.startsWith("\\") ||
                    containsTraversal(rawName)) {
                throw new IOException("Unsafe OOXML ZIP entry path: " + rawName);
            }

            String partName = normalize(rawName);
            if (!seenNames.add(partName)) {
                throw new IOException("Duplicate OOXML ZIP entry: " + partName);
            }

            if (entry.getSize() > MAX_SINGLE_PART_BYTES) {
                throw new IOException("OOXML ZIP entry exceeds the single-part size limit: " + partName);
            }

            byte[] data;

            try (InputStream inputStream = zipFile.getInputStream(entry)) {
                data = readPartData(inputStream, partName, totalBytes);
            }

            totalBytes += data.length;


            packageData.addPart(
                    new OOXMLPart(
                            partName,
                            null,
                            data
                    )
            );
        }
    }


    private byte[] readPartData(
            InputStream inputStream,
            String partName,
            long bytesAlreadyRead)
            throws IOException {

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long partBytes = 0L;
        int read;

        while ((read = inputStream.read(buffer)) != -1) {
            if (partBytes > MAX_SINGLE_PART_BYTES - read ||
                    bytesAlreadyRead > MAX_TOTAL_UNCOMPRESSED_BYTES - partBytes - read) {
                throw new IOException(
                        "OOXML package exceeds its uncompressed size limit at: " + partName
                );
            }
            output.write(buffer, 0, read);
            partBytes += read;
        }

        return output.toByteArray();
    }


    private void readContentTypes(OOXMLPackage packageData) throws IOException {
        OOXMLPart part = packageData.getPart("[Content_Types].xml");
        if (part == null || part.getData() == null || part.getData().length == 0) {
            throw new IOException("OOXML package is missing [Content_Types].xml.");
        }

        try {
            Document document = parseXml(part.getData());
            Element root = document.getDocumentElement();
            if (root == null || !"Types".equals(localName(root)) ||
                    !CONTENT_TYPES_NAMESPACE.equals(root.getNamespaceURI())) {
                throw new IOException("Invalid OOXML [Content_Types].xml root element or namespace.");
            }

            NodeList children = root.getChildNodes();
            int declarations = 0;
            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                if (!(node instanceof Element element)) continue;
                String localName = localName(element);
                if ("Default".equals(localName)) {
                    String extension = element.getAttribute("Extension").trim();
                    String contentType = element.getAttribute("ContentType").trim();
                    if (extension.isBlank() || contentType.isBlank()) {
                        throw new IOException("Invalid Default content-type declaration in [Content_Types].xml.");
                    }
                    packageData.addContentType("." + extension, contentType);
                    declarations++;
                } else if ("Override".equals(localName)) {
                    String partName = element.getAttribute("PartName").trim();
                    String contentType = element.getAttribute("ContentType").trim();
                    if (partName.isBlank() || contentType.isBlank() ||
                            !partName.startsWith("/")) {
                        throw new IOException("Invalid Override content-type declaration in [Content_Types].xml.");
                    }
                    packageData.addContentType(normalize(partName), contentType);
                    declarations++;
                } else {
                    throw new IOException("Unexpected element in [Content_Types].xml: " + element.getNodeName());
                }
            }
            if (declarations == 0) {
                throw new IOException("OOXML [Content_Types].xml contains no content-type declarations.");
            }
            applyContentTypes(packageData);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("OOXML [Content_Types].xml could not be safely parsed.", e);
        }
    }

    private String localName(Element element) {
        String name = element.getLocalName();
        return name == null ? element.getNodeName() : name;
    }

    private void applyContentTypes(
            OOXMLPackage packageData) {

        for (OOXMLPart part :
                packageData.getParts()) {

            if (part == null ||
                    part.getPartName() == null) {

                continue;
            }


            String contentType =
                    packageData.getContentType(
                            part.getPartName()
                    );


            if (contentType == null) {

                String extension =
                        getExtension(
                                part.getPartName()
                        );


                if (extension != null) {

                    contentType =
                            packageData.getContentType(
                                    "." + extension
                            );
                }
            }


            if (contentType != null) {

                part.setContentType(
                        contentType
                );
            }
        }
    }


    private void validateXmlParts(OOXMLPackage packageData) throws IOException {
        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null || part.getData() == null) continue;
            String name = part.getPartName().toLowerCase(java.util.Locale.ROOT);
            if (!part.isXml() && !name.endsWith(".xml") && !name.endsWith(".rels")) continue;
            try {
                Document document = parseXml(part.getData());
                if (document.getDocumentElement() == null) {
                    throw new IOException("XML part has no document element: " + part.getPartName());
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("XML part could not be safely parsed: " + part.getPartName(), e);
            }
        }
    }

    private void readRelationships(
            OOXMLPackage packageData) throws IOException {

        List<OOXMLPart> relationshipParts =
                new ArrayList<>();


        for (OOXMLPart part :
                packageData.getParts()) {

            if (part == null ||
                    part.getPartName() == null) {

                continue;
            }


            if (isRelationshipPart(
                    part.getPartName()
            )) {

                relationshipParts.add(
                        part
                );
            }
        }


        for (OOXMLPart relationshipPart :
                relationshipParts) {

            readRelationshipPart(
                    relationshipPart,
                    packageData
            );
        }
    }


    private void readRelationshipPart(OOXMLPart relationshipPart, OOXMLPackage packageData) throws IOException {
        try {
            Document document = parseXml(relationshipPart.getData());
            Element root = document.getDocumentElement();
            if (root == null || !"Relationships".equals(localName(root)) ||
                    !RELATIONSHIP_NAMESPACE.equals(root.getNamespaceURI())) {
                throw new IOException("Invalid OOXML relationship-part root or namespace: " + relationshipPart.getPartName());
            }

            String sourcePart = getSourcePartFromRelationshipPart(relationshipPart.getPartName());
            NodeList children = root.getChildNodes();
            java.util.HashSet<String> ids = new java.util.HashSet<>();
            for (int i = 0; i < children.getLength(); i++) {
                Node node = children.item(i);
                if (!(node instanceof Element element)) continue;
                if (!"Relationship".equals(localName(element))) {
                    throw new IOException("Unexpected element in relationship part: " + relationshipPart.getPartName());
                }
                String id = element.getAttribute("Id").trim();
                String type = element.getAttribute("Type").trim();
                String target = element.getAttribute("Target").trim();
                String targetMode = element.getAttribute("TargetMode").trim();
                if (id.isBlank() || type.isBlank() || target.isBlank() || !ids.add(id)) {
                    throw new IOException("Invalid or duplicate relationship in: " + relationshipPart.getPartName());
                }
                if (!targetMode.isBlank() && !"External".equalsIgnoreCase(targetMode)) {
                    throw new IOException("Unsupported OOXML relationship TargetMode in: " + relationshipPart.getPartName());
                }
                packageData.addRelationship(new OOXMLRelationship(
                        sourcePart, id, type, target, targetMode.isBlank() ? null : targetMode));
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("OOXML relationship part could not be safely parsed: " + relationshipPart.getPartName(), e);
        }
    }

    private Document parseXml(
            byte[] data)
            throws Exception {

        if (data == null) {

            throw new IllegalArgumentException(
                    "XML data cannot be null."
            );
        }


        DocumentBuilderFactory factory =
                security.sandbox.SecureXmlFactory.createSecureDocumentBuilderFactory();

        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

        DocumentBuilder builder = factory.newDocumentBuilder();


        try (
                ByteArrayInputStream input =
                        new ByteArrayInputStream(
                                data
                        )
        ) {

            return builder.parse(
                    input
            );
        }
    }


    private boolean isRelationshipPart(
            String partName) {

        return partName != null &&
                (
                        partName.equals(
                                "_rels/.rels"
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


    private boolean containsTraversal(String value) {

        if (value == null) return false;
        String normalized = value.replace('\\', '/');
        for (String segment : normalized.split("/")) {
            if ("..".equals(segment)) return true;
        }
        return false;
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


    private String getExtension(
            String partName) {

        int index =
                partName.lastIndexOf('.');


        if (index < 0 ||
                index == partName.length() - 1) {

            return null;
        }


        return partName.substring(
                index + 1
        ).toLowerCase();
    }
}