package threat.xlsx;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;
import threat.common.SecurityFinding;

import java.nio.file.Path;
import java.util.List;

public class XLSXThreatAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.xlsx.XLSXThreatAnalyzerTest <file.xlsx>"
            );

            System.exit(1);
        }

        try {

            Path input =
                    Path.of(args[0]);

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage packageData =
                    reader.read(input);

            XLSXThreatAnalyzer analyzer =
                    new XLSXThreatAnalyzer();

            List<SecurityFinding> findings =
                    analyzer.analyze(
                            packageData
                    );

            System.out.println(
                    "Findings : " +
                    findings.size()
            );

            for (SecurityFinding finding :
                    findings) {

                System.out.println();

                System.out.println(
                        "Part         : " +
                        finding.getPartName()
                );

                System.out.println(
                        "Classification: " +
                        finding.getClassification()
                );

                System.out.println(
                        "Type         : " +
                        finding.getType()
                );

                System.out.println(
                        "Severity     : " +
                        finding.getSeverity()
                );

                System.out.println(
                        "Source Part  : " +
                        finding.getSourcePart()
                );

                System.out.println(
                        "Relationship : " +
                        finding.getRelationshipId()
                );
            }

            boolean detected =
                    findings.stream()
                            .anyMatch(
                                    finding ->
                                            finding.getType() ==
                                                    threat.common.ThreatType.VBA_PROJECT
                            );

            if (!detected) {

                throw new AssertionError(
                        "VBA project was not detected."
                );
            }

            System.out.println();
            System.out.println(
                    "XLSX THREAT ANALYZER TEST PASSED"
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "XLSX THREAT ANALYZER TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}