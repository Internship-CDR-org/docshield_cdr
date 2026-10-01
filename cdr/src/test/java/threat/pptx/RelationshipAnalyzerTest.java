package threat.pptx;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import parsing.pptx.PPTXRelationshipGraph;
import threat.common.SecurityFinding;

import java.util.List;

public class RelationshipAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.pptx.RelationshipAnalyzerTest <file.pptx>"
            );

            System.exit(1);
        }

        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "          RELATIONSHIP ANALYZER"
            );

            System.out.println(
                    "=============================================="
            );

            // -------------------------------------------------
            // READ PACKAGE
            // -------------------------------------------------

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pptxPackage =
                    reader.read(args[0]);

            System.out.println();
            System.out.println(
                    "Parts         : "
                            + pptxPackage.getPartCount()
            );

            System.out.println(
                    "Relationships : "
                            + pptxPackage.getRelationshipCount()
            );

            // -------------------------------------------------
            // BUILD RELATIONSHIP GRAPH
            // -------------------------------------------------

            PPTXRelationshipGraph graph =
                    new PPTXRelationshipGraph(
                            pptxPackage
                    );

            // -------------------------------------------------
            // ANALYZE
            // -------------------------------------------------

            RelationshipAnalyzer analyzer =
                    new RelationshipAnalyzer();

            List<SecurityFinding> findings =
                    analyzer.analyze(graph);

            // -------------------------------------------------
            // RESULTS
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "Findings : "
                            + findings.size()
            );

            System.out.println();

            for (SecurityFinding finding :
                    findings) {

                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "Classification : "
                                + finding.getClassification()
                );

                System.out.println(
                        "Type           : "
                                + finding.getType()
                );

                System.out.println(
                        "Severity       : "
                                + finding.getSeverity()
                );

                System.out.println(
                        "Part           : "
                                + finding.getPartName()
                );

                System.out.println(
                        "Evidence       : "
                                + finding.getEvidence()
                );

                System.out.println(
                        "Description    : "
                                + finding.getDescription()
                );

                System.out.println(
                        "Action         : "
                                + finding.getRecommendedAction()
                );
            }

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       RELATIONSHIP ANALYSIS COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "RELATIONSHIP ANALYSIS FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}
