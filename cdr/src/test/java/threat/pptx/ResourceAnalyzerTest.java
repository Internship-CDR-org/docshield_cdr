package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import parsing.pptx.PPTXRelationshipGraph;

import java.util.List;


/**
 * Integration test for ResourceAnalyzer.
 *
 * This test only observes referenced resources.
 * It does NOT modify the PPTX.
 */
public class ResourceAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.ResourceAnalyzerTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "          RESOURCE ANALYZER TEST"
            );

            System.out.println(
                    "=============================================="
            );


            // =================================================
            // READ PACKAGE
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pptxPackage =
                    reader.read(args[0]);


            System.out.println(
                    "Package parts : " +
                    pptxPackage.getPartCount()
            );

            System.out.println(
                    "Relationships : " +
                    pptxPackage.getRelationshipCount()
            );


            // =================================================
            // BUILD RELATIONSHIP GRAPH
            // =================================================

            PPTXRelationshipGraph graph =
                    new PPTXRelationshipGraph(
                            pptxPackage
                    );


            System.out.println(
                    "Graph edges   : " +
                    graph.getEdgeCount()
            );


            // =================================================
            // CREATE ANALYZER
            // =================================================

            ResourceAnalyzer analyzer =
                    new ResourceAnalyzer();


            // =================================================
            // ANALYZE
            // =================================================

            List<SecurityFinding> findings =
                    analyzer.analyze(
                            graph
                    );


            System.out.println();
            System.out.println(
                    "Resource findings : " +
                    findings.size()
            );


            // =================================================
            // DISPLAY
            // =================================================

            System.out.println();
            System.out.println(
                    "========== REFERENCED RESOURCES =========="
            );


            for (SecurityFinding finding :
                    findings) {

                System.out.println();

                System.out.println(
                        "Target part     : " +
                        finding.getPartName()
                );

                System.out.println(
                        "Content type    : " +
                        finding.getPart().getContentType()
                );

                System.out.println(
                        "Classification  : " +
                        finding.getClassification()
                );

                System.out.println(
                        "Type            : " +
                        finding.getType()
                );

                System.out.println(
                        "Source part     : " +
                        finding.getSourcePart()
                );

                System.out.println(
                        "Relationship ID : " +
                        finding.getRelationshipId()
                );

                System.out.println(
                        "Evidence        : " +
                        finding.getEvidence()
                );
            }


            // =================================================
            // COMPLETE
            // =================================================

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "RESOURCE ANALYSIS COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "RESOURCE ANALYSIS FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}