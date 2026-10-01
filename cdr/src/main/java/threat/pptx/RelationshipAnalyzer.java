package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLRelationship;
import parsing.pptx.PPTXRelationshipGraph;

import java.util.ArrayList;
import java.util.List;


/**
 * Analyzes PPTX relationships and produces security observations.
 *
 * This analyzer does NOT modify the PPTX package.
 *
 * External relationships are observations, not automatically threats.
 */
public class RelationshipAnalyzer
        implements SecurityAnalyzer<PPTXRelationshipGraph> {


    @Override
    public List<SecurityFinding> analyze(
            PPTXRelationshipGraph graph) {

        List<SecurityFinding> findings =
                new ArrayList<>();


        if (graph == null) {
            return findings;
        }


        // =====================================================
        // ANALYZE ALL RELATIONSHIPS
        // =====================================================

        for (PPTXRelationshipGraph.Edge edge :
                graph.getAllEdges()) {

            if (edge == null) {
                continue;
            }


            OOXMLRelationship relationship =
                    edge.getRelationship();


            if (relationship == null) {
                continue;
            }


            // =================================================
            // EXTERNAL RELATIONSHIP
            // =================================================

            if (edge.isExternal()) {

                ThreatType type =
                        determineExternalType(
                                relationship
                        );


                String description =
                        "The package contains an external relationship.";


                String evidence =
                        "Source: " +
                        edge.getSourcePart() +
                        ", relationship ID: " +
                        relationship.getId() +
                        ", target: " +
                        edge.getTarget();


                findings.add(
                        new SecurityFinding(
                                FindingClassification.OBSERVATION,
                                type,
                                ThreatSeverity.INFO,
                                null,
                                edge.getSourcePart(),
                                relationship.getId(),
                                evidence,
                                description,
                                "Analyze the external target according to CDR policy."
                        )
                );
            }


            // =================================================
            // LOCAL RELATIONSHIP WITH MISSING TARGET
            // =================================================

            else if (edge.getTarget() != null &&
                    !edge.targetExists()) {

                String evidence =
                        "Source: " +
                        edge.getSourcePart() +
                        ", relationship ID: " +
                        relationship.getId() +
                        ", target: " +
                        edge.getTarget() +
                        ", resolved target: " +
                        edge.getResolvedTargetPart();


                findings.add(
                        new SecurityFinding(
                                FindingClassification.SUSPICIOUS,
                                ThreatType.MISSING_TARGET,
                                ThreatSeverity.MEDIUM,
                                null,
                                edge.getSourcePart(),
                                relationship.getId(),
                                evidence,
                                "A local relationship points to a package part that does not exist.",
                                "Investigate the broken relationship before reconstruction."
                        )
                );
            }
        }


        return findings;
    }


    // =========================================================
    // DETERMINE EXTERNAL RELATIONSHIP TYPE
    // =========================================================

    private ThreatType determineExternalType(
            OOXMLRelationship relationship) {

        String type =
                relationship.getType();


        if (type != null &&
                type.toLowerCase()
                        .contains("hyperlink")) {

            return ThreatType.EXTERNAL_HYPERLINK;
        }


        return ThreatType.EXTERNAL_REFERENCE;
    }
}