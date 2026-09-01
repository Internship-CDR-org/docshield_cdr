package parsing.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import java.nio.file.Path;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class PPTXContentInspectorTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java parsing.pptx.PPTXContentInspectorTest <file.pptx>"
            );

            System.exit(1);
        }

        Path pptxPath = Path.of(args[0]);

        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "       PPTX CONTENT INSPECTOR TEST"
            );
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Input : " + pptxPath
            );

            System.out.println();


            // =================================================
            // READ PACKAGE
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pptxPackage =
                    reader.read(pptxPath);


            System.out.println(
                    "Package parts : " +
                    pptxPackage.getPartCount()
            );

            System.out.println(
                    "Relationships : " +
                    pptxPackage.getRelationshipCount()
            );

            System.out.println();


            // =================================================
            // INSPECT PACKAGE
            // =================================================

            PPTXContentInspector inspector =
                    new PPTXContentInspector();

            List<PPTXContentInspector.InspectionResult> results =
                    inspector.inspect(pptxPackage);


            // =================================================
            // COUNT CATEGORIES
            // =================================================

            Map<PPTXContentInspector.PartCategory, Integer> counts =
                    new EnumMap<>(
                            PPTXContentInspector.PartCategory.class
                    );


            for (PPTXContentInspector.InspectionResult result :
                    results) {

                PPTXContentInspector.PartCategory category =
                        result.getCategory();

                counts.put(
                        category,
                        counts.getOrDefault(category, 0) + 1
                );
            }


            // =================================================
            // CATEGORY SUMMARY
            // =================================================

            System.out.println(
                    "========== CATEGORY SUMMARY =========="
            );


            for (PPTXContentInspector.PartCategory category :
                    PPTXContentInspector.PartCategory.values()) {

                int count =
                        counts.getOrDefault(
                                category,
                                0
                        );

                if (count > 0) {

                    System.out.printf(
                            "%-20s : %d%n",
                            category,
                            count
                    );
                }
            }


            System.out.println();


            // =================================================
            // DETAILED INVENTORY
            // =================================================

            System.out.println(
                    "========== DETAILED INVENTORY =========="
            );


            for (PPTXContentInspector.InspectionResult result :
                    results) {

                OOXMLPart part =
                        result.getPart();


                System.out.println(
                        result.getCategory() +
                        " | " +
                        result.getPartName() +
                        " | " +
                        result.getContentType() +
                        " | " +
                        (
                                part.getData() == null
                                        ? 0
                                        : part.getData().length
                        ) +
                        " bytes"
                );
            }


            System.out.println();


            // =================================================
            // COMPLETE
            // =================================================

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "CONTENT INSPECTION COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "CONTENT INSPECTOR TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}