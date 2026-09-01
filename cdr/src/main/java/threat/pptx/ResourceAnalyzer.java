package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPart;
import parsing.pptx.PPTXRelationshipGraph;

import java.util.ArrayList;
import java.util.List;


/**
 * Identifies content-bearing resources referenced inside a PPTX package.
 *
 * This class performs inventory/classification only.
 * It does NOT decide whether a resource is malicious.
 * It does NOT modify the package.
 */
public class ResourceAnalyzer
        implements SecurityAnalyzer<PPTXRelationshipGraph> {


    @Override
    public List<SecurityFinding> analyze(
            PPTXRelationshipGraph graph) {

        List<SecurityFinding> findings =
                new ArrayList<>();


        if (graph == null) {
            return findings;
        }


        for (PPTXRelationshipGraph.Edge edge :
                graph.getAllEdges()) {

            if (edge == null ||
                    edge.isExternal() ||
                    !edge.targetExists()) {

                continue;
            }


            OOXMLPart targetPart =
                    graph.getTargetPart(edge);


            if (targetPart == null) {
                continue;
            }


            ThreatType type =
                    determineResourceType(targetPart);


            /*
             * UNKNOWN means that this is not currently classified
             * as a content-bearing resource.
             *
             * Structural package parts such as slides, layouts,
             * masters, themes and notes are intentionally ignored.
             */
            if (type == ThreatType.UNKNOWN) {
                continue;
            }


            String contentType =
                    targetPart.getContentType();


            String description =
                    "A content-bearing package resource is referenced.";


            String evidence =
                    "Source: " +
                    edge.getSourcePart() +
                    ", relationship ID: " +
                    edge.getRelationship().getId() +
                    ", target: " +
                    edge.getResolvedTargetPart() +
                    ", content type: " +
                    contentType;


            findings.add(
                    new SecurityFinding(
                            FindingClassification.OBSERVATION,
                            type,
                            ThreatSeverity.INFO,
                            targetPart,
                            edge.getSourcePart(),
                            edge.getRelationship().getId(),
                            evidence,
                            description,
                            "Route this resource to the appropriate content analyzer."
                    )
            );
        }


        return findings;
    }


    // =========================================================
    // RESOURCE CLASSIFICATION
    // =========================================================

    private ThreatType determineResourceType(
            OOXMLPart part) {

        if (part == null) {
            return ThreatType.UNKNOWN;
        }


        String contentType =
                part.getContentType();

        String partName =
                part.getPartName();


        String ct =
                contentType == null
                        ? ""
                        : contentType.toLowerCase();


        String name =
                partName == null
                        ? ""
                        : partName.toLowerCase();


        // =====================================================
        // OLE / EMBEDDED OBJECT
        // =====================================================

        if (name.contains("/embeddings/") ||
                ct.contains("oleobject") ||
                ct.equals("application/vnd.ms-office.oleObject")) {

            return ThreatType.EMBEDDED_OBJECT;
        }


        // =====================================================
        // SVG
        // =====================================================

        if (ct.equals("image/svg+xml") ||
                name.endsWith(".svg")) {

            return ThreatType.SVG_RESOURCE;
        }


        // =====================================================
        // RASTER IMAGES
        // =====================================================

        if (ct.equals("image/png") ||
                ct.equals("image/jpeg") ||
                ct.equals("image/jpg") ||
                ct.equals("image/gif") ||
                ct.equals("image/bmp") ||
                ct.equals("image/tiff") ||
                name.endsWith(".png") ||
                name.endsWith(".jpg") ||
                name.endsWith(".jpeg") ||
                name.endsWith(".gif") ||
                name.endsWith(".bmp") ||
                name.endsWith(".tif") ||
                name.endsWith(".tiff")) {

            return ThreatType.IMAGE_RESOURCE;
        }


        // =====================================================
        // AUDIO
        // =====================================================

        if (ct.startsWith("audio/") ||
                name.endsWith(".mp3") ||
                name.endsWith(".wav") ||
                name.endsWith(".m4a") ||
                name.endsWith(".aac") ||
                name.endsWith(".wma")) {

            return ThreatType.AUDIO_RESOURCE;
        }


        // =====================================================
        // VIDEO
        // =====================================================

        if (ct.startsWith("video/") ||
                name.endsWith(".mp4") ||
                name.endsWith(".avi") ||
                name.endsWith(".mov") ||
                name.endsWith(".wmv") ||
                name.endsWith(".mkv")) {

            return ThreatType.VIDEO_RESOURCE;
        }


        // =====================================================
        // GENERIC BINARY
        // =====================================================

        if (ct.equals("application/octet-stream")) {

            return ThreatType.BINARY_RESOURCE;
        }


        return ThreatType.UNKNOWN;
    }
}