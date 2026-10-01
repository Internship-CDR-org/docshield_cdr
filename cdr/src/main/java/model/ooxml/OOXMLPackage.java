package model.ooxml;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the physical structure of an OOXML/OPC package.
 *
 * An OOXML package is a ZIP container containing:
 *
 *   - package parts
 *   - relationships
 *   - content type declarations
 *
 * This class is format-independent and can be used by
 * DOCX, PPTX and XLSX package processing.
 */
public class OOXMLPackage {

    private final Map<String, OOXMLPart> parts =
            new LinkedHashMap<>();

    private final List<OOXMLRelationship> relationships =
            new ArrayList<>();

    private final Map<String, String> contentTypes =
            new LinkedHashMap<>();


    // =========================================================
    // PARTS
    // =========================================================

    public void addPart(
            OOXMLPart part) {

        if (part == null ||
                part.getPartName() == null) {

            return;
        }

        parts.put(
                normalizePartName(
                        part.getPartName()
                ),
                part
        );
    }


    public OOXMLPart getPart(
            String partName) {

        if (partName == null) {
            return null;
        }

        return parts.get(
                normalizePartName(partName)
        );
    }


    public boolean hasPart(
            String partName) {

        return getPart(partName) != null;
    }


    public OOXMLPart removePart(
            String partName) {

        if (partName == null) {
            return null;
        }

        return parts.remove(
                normalizePartName(partName)
        );
    }


    public Collection<OOXMLPart> getParts() {

        return parts.values();
    }


    public int getPartCount() {

        return parts.size();
    }


    // =========================================================
    // RELATIONSHIPS
    // =========================================================

    public void addRelationship(
            OOXMLRelationship relationship) {

        if (relationship == null) {
            return;
        }

        relationships.add(
                relationship
        );
    }


    public List<OOXMLRelationship>
    getRelationships() {

        return relationships;
    }


    public List<OOXMLRelationship>
    getRelationshipsFrom(
            String sourcePart) {

        List<OOXMLRelationship> result =
                new ArrayList<>();

        String normalizedSource =
                normalizeNullable(
                        sourcePart
                );


        for (OOXMLRelationship relationship :
                relationships) {

            if (relationship == null) {
                continue;
            }


            String relationshipSource =
                    relationship.getSourcePart();


            String normalizedRelationshipSource =
                    normalizeNullable(
                            relationshipSource
                    );


            if (sameSource(
                    normalizedSource,
                    normalizedRelationshipSource
            )) {

                result.add(
                        relationship
                );
            }
        }


        return result;
    }


    /**
     * Removes a relationship by source part and relationship ID.
     *
     * A null sourcePart is valid because root relationships
     * originate from the package root.
     */
    public boolean removeRelationship(
            String sourcePart,
            String relationshipId) {

        if (relationshipId == null) {
            return false;
        }


        String normalizedSource =
                normalizeNullable(
                        sourcePart
                );


        return relationships.removeIf(
                relationship ->
                        relationship != null &&
                        sameSource(
                                normalizedSource,
                                normalizeNullable(
                                        relationship.getSourcePart()
                                )
                        ) &&
                        relationshipId.equals(
                                relationship.getId()
                        )
        );
    }


    /**
     * Removes all relationships originating from a part.
     *
     * A null sourcePart represents package-root relationships.
     */
    public void removeRelationshipsFrom(
            String sourcePart) {

        String normalizedSource =
                normalizeNullable(
                        sourcePart
                );


        relationships.removeIf(
                relationship ->
                        relationship != null &&
                        sameSource(
                                normalizedSource,
                                normalizeNullable(
                                        relationship.getSourcePart()
                                )
                        )
        );
    }


    /**
     * Removes a single content-type declaration.
     */
    public boolean removeContentType(String name) {

        if (name == null) {
            return false;
        }

        return contentTypes.remove(name) != null;
    }


    /**
     * Removes all relationships that resolve to the supplied local part.
     * External relationships are never resolved as package parts.
     */
    public int removeRelationshipsTargeting(String targetPart) {

        if (targetPart == null || targetPart.isBlank()) {
            return 0;
        }

        String normalizedTarget = normalizeRelativePath(
                normalizePartName(targetPart)
        );
        int[] removed = new int[] {0};

        relationships.removeIf(relationship -> {
            if (relationship == null ||
                    relationship.isExternal() ||
                    relationship.getTarget() == null) {
                return false;
            }

            String resolved = resolveRelationshipTarget(
                    relationship.getSourcePart(),
                    relationship.getTarget()
            );

            if (normalizedTarget.equals(resolved)) {
                removed[0]++;
                return true;
            }

            return false;
        });

        return removed[0];
    }


    private String resolveRelationshipTarget(
            String sourcePart,
            String target) {

        if (target == null || target.isBlank()) {
            return null;
        }

        String normalizedTarget = target.trim().replace('\\', '/');

        if (normalizedTarget.startsWith("/")) {
            return normalizeRelativePath(normalizedTarget);
        }

        if (sourcePart == null || sourcePart.isBlank()) {
            return normalizeRelativePath(normalizedTarget);
        }

        String source = normalizePartName(sourcePart);
        int slash = source.lastIndexOf('/');
        String directory = slash < 0 ? "" : source.substring(0, slash);

        return normalizeRelativePath(
                directory.isEmpty()
                        ? normalizedTarget
                        : directory + "/" + normalizedTarget
        );
    }


    public int getRelationshipCount() {

        return relationships.size();
    }


    // =========================================================
    // CONTENT TYPES
    // =========================================================

    public void addContentType(
            String name,
            String contentType) {

        if (name == null ||
                contentType == null) {

            return;
        }


        contentTypes.put(
                name,
                contentType
        );
    }


    public String getContentType(
            String name) {

        if (name == null) {
            return null;
        }

        return contentTypes.get(
                name
        );
    }


    public Map<String, String>
    getContentTypes() {

        return contentTypes;
    }


    // =========================================================
    // NORMALIZATION
    // =========================================================

    private String normalizeNullable(
            String value) {

        if (value == null) {
            return null;
        }

        return normalizePartName(
                value
        );
    }


    private String normalizePartName(
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


    private String normalizeRelativePath(String path) {

        if (path == null) {
            return null;
        }

        String[] pieces = path.replace('\\', '/').split("/");
        List<String> result = new ArrayList<>();

        for (String piece : pieces) {
            if (piece.isEmpty() || ".".equals(piece)) {
                continue;
            }

            if ("..".equals(piece)) {
                if (!result.isEmpty()) {
                    result.remove(result.size() - 1);
                }
                continue;
            }

            result.add(piece);
        }

        return String.join("/", result);
    }


    private boolean sameSource(
            String first,
            String second) {

        if (first == null &&
                second == null) {

            return true;
        }


        if (first == null ||
                second == null) {

            return false;
        }


        return first.equals(
                second
        );
    }


    // =========================================================
    // STRING REPRESENTATION
    // =========================================================

    @Override
    public String toString() {

        return "OOXMLPackage{" +
                "parts=" +
                parts.size() +
                ", relationships=" +
                relationships.size() +
                ", contentTypes=" +
                contentTypes.size() +
                '}';
    }
}