package parsing.pptx;

import parsing.common.DocumentParser;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Builds a navigable relationship graph over a PPTX package.
 *
 * This class does NOT modify the package.
 *
 * It resolves relationship targets so that callers can move from:
 *
 *     source part
 *          |
 *          | relationship
 *          v
 *     target part
 *
 * Example:
 *
 *     ppt/slides/slide2.xml
 *             |
 *             | rId3
 *             v
 *     ppt/media/image-2-3.svg
 *
 * External relationships are kept as external targets and are
 * never converted into local package parts.
 */
public class PPTXRelationshipGraph {


    // =========================================================
    // GRAPH EDGE
    // =========================================================

    public static class Edge {

        private final OOXMLRelationship relationship;

        private final String sourcePart;

        private final String target;

        private final String resolvedTargetPart;

        private final boolean external;

        private final boolean targetExists;


        private Edge(
                OOXMLRelationship relationship,
                String sourcePart,
                String target,
                String resolvedTargetPart,
                boolean external,
                boolean targetExists) {

            this.relationship = relationship;
            this.sourcePart = sourcePart;
            this.target = target;
            this.resolvedTargetPart = resolvedTargetPart;
            this.external = external;
            this.targetExists = targetExists;
        }


        public OOXMLRelationship getRelationship() {
            return relationship;
        }


        public String getSourcePart() {
            return sourcePart;
        }


        public String getTarget() {
            return target;
        }


        public String getResolvedTargetPart() {
            return resolvedTargetPart;
        }


        public boolean isExternal() {
            return external;
        }


        public boolean targetExists() {
            return targetExists;
        }


        @Override
        public String toString() {

            return sourcePart +
                    " | " +
                    relationship.getId() +
                    " | " +
                    relationship.getType() +
                    " | " +
                    target +
                    " | resolved=" +
                    resolvedTargetPart +
                    " | external=" +
                    external +
                    " | exists=" +
                    targetExists;
        }
    }


    // =========================================================
    // GRAPH STORAGE
    // =========================================================

    private final OOXMLPackage pptxPackage;


    private final Map<String, List<Edge>> outgoing =
            new LinkedHashMap<>();


    private final Map<String, List<Edge>> incoming =
            new LinkedHashMap<>();


    private final List<Edge> externalEdges =
            new ArrayList<>();


    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public PPTXRelationshipGraph(
            OOXMLPackage pptxPackage) {

        if (pptxPackage == null) {

            throw new IllegalArgumentException(
                    "PPTX package cannot be null."
            );
        }


        this.pptxPackage =
                pptxPackage;


        build();
    }


    // =========================================================
    // BUILD GRAPH
    // =========================================================

    private void build() {

        for (OOXMLRelationship relationship :
                pptxPackage.getRelationships()) {

            if (relationship == null) {
                continue;
            }


            String sourcePart =
                    normalizePartName(
                            relationship.getSourcePart()
                    );


            String target =
                    relationship.getTarget();


            boolean external =
                    isExternalRelationship(
                            relationship
                    );


            String resolvedTarget =
                    null;


            boolean targetExists =
                    false;


            if (!external &&
                    target != null &&
                    !target.isBlank()) {

                resolvedTarget =
                        resolveTarget(
                                sourcePart,
                                target
                        );


                targetExists =
                        pptxPackage.hasPart(
                                resolvedTarget
                        );
            }


            Edge edge =
                    new Edge(
                            relationship,
                            sourcePart,
                            target,
                            resolvedTarget,
                            external,
                            targetExists
                    );


            outgoing
                    .computeIfAbsent(
                            sourcePart,
                            key -> new ArrayList<>()
                    )
                    .add(edge);


            if (resolvedTarget != null) {

                incoming
                        .computeIfAbsent(
                                resolvedTarget,
                                key -> new ArrayList<>()
                        )
                        .add(edge);
            }


            if (external) {

                externalEdges.add(
                        edge
                );
            }
        }
    }


    // =========================================================
    // OUTGOING RELATIONSHIPS
    // =========================================================

    /**
     * Returns all relationships originating from a part.
     */
    public List<Edge> getOutgoing(
            String sourcePart) {

        if (sourcePart == null) {

            return Collections.emptyList();
        }


        List<Edge> edges =
                outgoing.get(
                        normalizePartName(
                                sourcePart
                        )
                );


        if (edges == null) {

            return Collections.emptyList();
        }


        return Collections.unmodifiableList(
                edges
        );
    }


    /**
     * Finds one relationship by relationship ID.
     */
    public Edge getOutgoingById(
            String sourcePart,
            String relationshipId) {

        if (sourcePart == null ||
                relationshipId == null) {

            return null;
        }


        for (Edge edge :
                getOutgoing(sourcePart)) {

            if (relationshipId.equals(
                    edge.getRelationship().getId()
            )) {

                return edge;
            }
        }


        return null;
    }


    // =========================================================
    // INCOMING RELATIONSHIPS
    // =========================================================

    /**
     * Returns all relationships pointing to a package part.
     */
    public List<Edge> getIncoming(
            String targetPart) {

        if (targetPart == null) {

            return Collections.emptyList();
        }


        List<Edge> edges =
                incoming.get(
                        normalizePartName(
                                targetPart
                        )
                );


        if (edges == null) {

            return Collections.emptyList();
        }


        return Collections.unmodifiableList(
                edges
        );
    }


    // =========================================================
    // EXTERNAL RELATIONSHIPS
    // =========================================================

    /**
     * Returns all relationships whose TargetMode is External
     * or whose target is otherwise recognized as an external URI.
     */
    public List<Edge> getExternalEdges() {

        return Collections.unmodifiableList(
                externalEdges
        );
    }


    // =========================================================
    // TARGET RESOLUTION
    // =========================================================

    /**
     * Resolves a relationship target relative to its source part.
     *
     * Example:
     *
     * source:
     *     ppt/slides/slide2.xml
     *
     * target:
     *     ../media/image1.png
     *
     * result:
     *     ppt/media/image1.png
     *
     * Root relationships have a null source part and are resolved
     * relative to the package root.
     */
    public String resolveTarget(
            String sourcePart,
            String target) {

        if (target == null ||
                target.isBlank()) {

            return null;
        }


        String normalizedTarget =
                target
                        .replace(
                                '\\',
                                '/'
                        )
                        .trim();


        // -----------------------------------------------------
        // Absolute package path
        // -----------------------------------------------------

        if (normalizedTarget.startsWith("/")) {

            return normalizePartName(
                    normalizedTarget
            );
        }


        // -----------------------------------------------------
        // External-looking URI
        // -----------------------------------------------------

        if (looksLikeUri(
                normalizedTarget
        )) {

            return null;
        }


        // -----------------------------------------------------
        // Root relationship
        // -----------------------------------------------------

        if (sourcePart == null ||
                sourcePart.isBlank()) {

            return normalizeRelativePath(
                    normalizedTarget
            );
        }


        // -----------------------------------------------------
        // Resolve relative to source directory
        // -----------------------------------------------------

        Path sourcePath =
                Path.of(
                        sourcePart
                );


        Path parent =
                sourcePath.getParent();


        String combined;


        if (parent == null) {

            combined =
                    normalizedTarget;

        } else {

            combined =
                    parent
                            .resolve(
                                    normalizedTarget
                            )
                            .toString()
                            .replace(
                                    '\\',
                                    '/'
                            );
        }


        return normalizeRelativePath(
                combined
        );
    }


    // =========================================================
    // RELATIONSHIP LOOKUP
    // =========================================================

    /**
     * Returns the package part referenced by a relationship.
     *
     * Returns null when:
     *
     * - relationship does not exist
     * - target is external
     * - target does not exist
     */
    public OOXMLPart getTargetPart(
            String sourcePart,
            String relationshipId) {

        Edge edge =
                getOutgoingById(
                        sourcePart,
                        relationshipId
                );


        if (edge == null ||
                edge.isExternal() ||
                !edge.targetExists()) {

            return null;
        }


        return pptxPackage.getPart(
                edge.getResolvedTargetPart()
        );
    }


    /**
     * Returns the target part directly from an edge.
     */
    public OOXMLPart getTargetPart(
            Edge edge) {

        if (edge == null ||
                edge.isExternal() ||
                !edge.targetExists()) {

            return null;
        }


        return pptxPackage.getPart(
                edge.getResolvedTargetPart()
        );
    }


    // =========================================================
    // GRAPH INFORMATION
    // =========================================================

    public int getEdgeCount() {

        int count = 0;


        for (List<Edge> edges :
                outgoing.values()) {

            count += edges.size();
        }


        return count;
    }


    public int getExternalEdgeCount() {

        return externalEdges.size();
    }


    /**
     * Returns all graph edges.
     */
    public List<Edge> getAllEdges() {

        List<Edge> result =
                new ArrayList<>();


        for (List<Edge> edges :
                outgoing.values()) {

            result.addAll(
                    edges
            );
        }


        return Collections.unmodifiableList(
                result
        );
    }


    // =========================================================
    // RELATIONSHIP TYPE HELPERS
    // =========================================================

    /**
     * Returns true if a relationship points outside the package.
     */
    private boolean isExternalRelationship(
            OOXMLRelationship relationship) {

        if (relationship == null) {
            return false;
        }


        String targetMode =
                relationship.getTargetMode();


        if (targetMode != null &&
                "external".equalsIgnoreCase(
                        targetMode.trim()
                )) {

            return true;
        }


        String target =
                relationship.getTarget();


        return target != null &&
                looksLikeUri(
                        target.trim()
                );
    }


    private boolean looksLikeUri(
            String value) {

        if (value == null ||
                value.isBlank()) {

            return false;
        }


        try {

            URI uri =
                    URI.create(
                            value
                    );


            return uri.isAbsolute();

        } catch (Exception ignored) {

            return false;
        }
    }


    // =========================================================
    // PATH NORMALIZATION
    // =========================================================

    private String normalizePartName(
            String partName) {

        if (partName == null) {
            return null;
        }


        String normalized =
                partName
                        .trim()
                        .replace(
                                '\\',
                                '/'
                        );


        while (normalized.startsWith("/")) {

            normalized =
                    normalized.substring(1);
        }


        return normalizeRelativePath(
                normalized
        );
    }


    private String normalizeRelativePath(
            String path) {

        if (path == null) {
            return null;
        }


        String normalized =
                path
                        .replace(
                                '\\',
                                '/'
                        );


        String[] pieces =
                normalized.split(
                        "/"
                );


        List<String> result =
                new ArrayList<>();


        for (String piece :
                pieces) {

            if (piece.isEmpty() ||
                    ".".equals(piece)) {

                continue;
            }


            if ("..".equals(piece)) {

                if (!result.isEmpty()) {

                    result.remove(
                            result.size() - 1
                    );
                }

                continue;
            }


            result.add(
                    piece
            );
        }


        return String.join(
                "/",
                result
        );
    }
}