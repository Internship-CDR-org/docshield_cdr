package reconstruction;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import parsing.ooxml.OOXMLPackageReader;
import parsing.pptx.PPTXRelationshipGraph;

public class PPTXReconstructionIntegrityTest {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println(
                    "Usage: java reconstruction.PPTXReconstructionIntegrityTest <file.pptx>"
            );
            System.exit(1);
        }

        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "       PPTX RECONSTRUCTION INTEGRITY TEST"
            );
            System.out.println(
                    "=============================================="
            );

            // -------------------------------------------------
            // READ PACKAGE
            // -------------------------------------------------

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage packageData =
                    reader.read(args[0]);

            System.out.println();
            System.out.println(
                    "Parts         : "
                            + packageData.getPartCount()
            );

            System.out.println(
                    "Relationships : "
                            + packageData.getRelationshipCount()
            );

            // -------------------------------------------------
            // BUILD RELATIONSHIP GRAPH
            // -------------------------------------------------

            PPTXRelationshipGraph graph =
                    new PPTXRelationshipGraph(
                            packageData
                    );

            System.out.println(
                    "Graph edges   : "
                            + graph.getEdgeCount()
            );

            System.out.println(
                    "External edges: "
                            + graph.getExternalEdgeCount()
            );

            // -------------------------------------------------
            // VALIDATE RELATIONSHIPS
            // -------------------------------------------------

            int brokenRelationships = 0;

            for (PPTXRelationshipGraph.Edge edge :
                    graph.getAllEdges()) {

                if (edge == null) {
                    continue;
                }

                // External relationships are allowed
                // to have no local target part.
                if (edge.isExternal()) {
                    continue;
                }

                if (edge.getResolvedTargetPart() == null) {

                    brokenRelationships++;

                    System.out.println(
                            "BROKEN: "
                                    + edge
                    );

                    continue;
                }

                if (!edge.targetExists()) {

                    brokenRelationships++;

                    System.out.println(
                            "BROKEN: "
                                    + edge
                    );

                    continue;
                }

                OOXMLPart targetPart =
                        packageData.getPart(
                                edge.getResolvedTargetPart()
                        );

                if (targetPart == null) {

                    brokenRelationships++;

                    System.out.println(
                            "BROKEN: "
                                    + edge
                    );
                }
            }

            // -------------------------------------------------
            // CHECK EMBEDDED PARTS
            // -------------------------------------------------

            int embeddedParts = 0;

            for (OOXMLPart part :
                    packageData.getParts()) {

                if (part == null ||
                        part.getPartName() == null) {

                    continue;
                }

                String name =
                        part.getPartName()
                                .toLowerCase();

                if (name.contains("/embeddings/")) {

                    embeddedParts++;

                    System.out.println(
                            "Embedded part: "
                                    + part.getPartName()
                    );
                }
            }

            // -------------------------------------------------
            // RESULTS
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "Broken relationships : "
                            + brokenRelationships
            );

            System.out.println(
                    "Embedded parts       : "
                            + embeddedParts
            );

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            if (brokenRelationships > 0) {

                System.out.println(
                        "       INTEGRITY TEST FAILED"
                );

                System.out.println(
                        "=============================================="
                );

                throw new IllegalStateException(
                        "Reconstructed package contains broken internal relationships."
                );
            }

            System.out.println(
                    "       INTEGRITY TEST PASSED"
            );

            System.out.println(
                    "=============================================="
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "INTEGRITY TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}