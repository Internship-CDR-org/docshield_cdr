package parsing.pptx;
import parsing.ooxml.OOXMLPackageReader;

import model.ooxml.OOXMLPackage;

public class PPTXRelationshipGraphTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java parsing.pptx.PPTXRelationshipGraphTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "       PPTX RELATIONSHIP GRAPH TEST"
            );
            System.out.println(
                    "=============================================="
            );


            // -------------------------------------------------
            // Read package
            // -------------------------------------------------

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();


            OOXMLPackage pptxPackage =
                    reader.read(
                            args[0]
                    );


            // -------------------------------------------------
            // Build graph
            // -------------------------------------------------

            PPTXRelationshipGraph graph =
                    new PPTXRelationshipGraph(
                            pptxPackage
                    );


            System.out.println(
                    "Graph edges       : " +
                    graph.getEdgeCount()
            );


            System.out.println(
                    "External edges    : " +
                    graph.getExternalEdgeCount()
            );


            System.out.println();


            // -------------------------------------------------
            // Show slide relationships
            // -------------------------------------------------

            System.out.println(
                    "========== SLIDE RELATIONSHIPS =========="
            );


            for (int i = 1; i <= 7; i++) {

                String slide =
                        "ppt/slides/slide" +
                        i +
                        ".xml";


                System.out.println();
                System.out.println(
                        slide
                );


                for (PPTXRelationshipGraph.Edge edge :
                        graph.getOutgoing(slide)) {

                    System.out.println(
                            "  " + edge
                    );
                }
            }


            // -------------------------------------------------
            // Show external relationships
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "========== EXTERNAL RELATIONSHIPS =========="
            );


            if (graph.getExternalEdges().isEmpty()) {

                System.out.println(
                        "  None"
                );

            } else {

                for (PPTXRelationshipGraph.Edge edge :
                        graph.getExternalEdges()) {

                    System.out.println(
                            "  " + edge
                    );
                }
            }


            // -------------------------------------------------
            // Complete
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "RELATIONSHIP GRAPH TEST COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "RELATIONSHIP GRAPH TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}