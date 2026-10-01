package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import parsing.ooxml.OOXMLPackageReader;

import java.util.List;


/**
 * Test for SVGAnalyzer.
 *
 * This test inspects the actual SVG bytes.
 * It does not modify the PPTX.
 */
public class SVGAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.SVGAnalyzerTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "             SVG ANALYZER TEST"
            );

            System.out.println(
                    "=============================================="
            );


            // =================================================
            // READ PPTX
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pptxPackage =
                    reader.read(args[0]);


            System.out.println(
                    "Package parts : " +
                    pptxPackage.getPartCount()
            );


            // =================================================
            // CREATE ANALYZER
            // =================================================

            SVGAnalyzer analyzer =
                    new SVGAnalyzer();


            int svgCount = 0;
            int findingCount = 0;


            // =================================================
            // INSPECT PACKAGE PARTS
            // =================================================

            for (OOXMLPart part :
                    pptxPackage.getParts()) {

                if (part == null) {
                    continue;
                }


                String contentType =
                        part.getContentType();


                String partName =
                        part.getPartName();


                boolean isSvg =
                        (contentType != null &&
                                contentType.equalsIgnoreCase(
                                        "image/svg+xml"
                                ))
                        ||
                        (partName != null &&
                                partName.toLowerCase()
                                        .endsWith(".svg"));


                if (!isSvg) {
                    continue;
                }


                svgCount++;


                List<SecurityFinding> findings =
                        analyzer.analyze(part);


                findingCount +=
                        findings.size();


                System.out.println();
                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "SVG : " +
                        partName
                );

                System.out.println(
                        "Findings : " +
                        findings.size()
                );


                for (SecurityFinding finding :
                        findings) {

                    System.out.println();

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
            }


            // =================================================
            // SUMMARY
            // =================================================

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "SVG resources inspected : " +
                    svgCount
            );

            System.out.println(
                    "Security findings       : " +
                    findingCount
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "SVG ANALYSIS COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "SVG ANALYSIS FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}