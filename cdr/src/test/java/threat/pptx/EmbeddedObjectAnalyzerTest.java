package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;

import java.util.List;


/**
 * Test for EmbeddedObjectAnalyzer.
 *
 * This test only inspects package content.
 * It never executes or modifies embedded objects.
 */
public class EmbeddedObjectAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.EmbeddedObjectAnalyzerTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       EMBEDDED OBJECT ANALYZER"
            );

            System.out.println(
                    "=============================================="
            );


            // =================================================
            // READ PACKAGE
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();


            OOXMLPackage packageData =
                    reader.read(args[0]);


            System.out.println(
                    "Package parts : " +
                    packageData.getPartCount()
            );


            // =================================================
            // ANALYZE
            // =================================================

            EmbeddedObjectAnalyzer analyzer =
                    new EmbeddedObjectAnalyzer();


            List<SecurityFinding> findings =
                    analyzer.analyze(
                            packageData
                    );


            System.out.println();
            System.out.println(
                    "Findings      : " +
                    findings.size()
            );


            // =================================================
            // DISPLAY
            // =================================================

            for (SecurityFinding finding :
                    findings) {

                System.out.println();
                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "Part           : " +
                        finding.getPartName()
                );

                System.out.println(
                        "Classification : " +
                        finding.getClassification()
                );

                System.out.println(
                        "Type           : " +
                        finding.getType()
                );

                System.out.println(
                        "Severity       : " +
                        finding.getSeverity()
                );

                System.out.println(
                        "Evidence       : " +
                        finding.getEvidence()
                );

                System.out.println(
                        "Description    : " +
                        finding.getDescription()
                );

                System.out.println(
                        "Action         : " +
                        finding.getRecommendedAction()
                );
            }


            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "EMBEDDED OBJECT ANALYSIS COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "EMBEDDED OBJECT ANALYSIS FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}