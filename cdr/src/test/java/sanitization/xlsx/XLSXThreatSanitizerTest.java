package sanitization.xlsx;

import model.ooxml.OOXMLPackage;

import parsing.ooxml.OOXMLPackageReader;

import reconstruction.OOXMLPackageWriter;

import threat.common.SecurityFinding;
import threat.xlsx.XLSXThreatAnalyzer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class XLSXThreatSanitizerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java sanitization.xlsx.XLSXThreatSanitizerTest <file.xlsx>"
            );

            System.exit(1);
        }

        Path input =
                Path.of(args[0]);

        Path output =
                Path.of(
                        "output",
                        "reconstructed",
                        "xlsx_vba_sanitized.xlsx"
                );

        try {

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
                    "Threat findings : " +
                    findings.size()
            );


            XLSXThreatSanitizer sanitizer =
                    new XLSXThreatSanitizer();

            List<String> actions =
                    sanitizer.sanitize(
                            packageData,
                            findings
                    );


            System.out.println(
                    "Sanitization actions : " +
                    actions.size()
            );


            for (String action :
                    actions) {

                System.out.println(
                        "  - " +
                        action
                );
            }


            if (packageData.hasPart(
                    "xl/vbaProject.bin"
            )) {

                throw new AssertionError(
                        "VBA project still exists after sanitization."
                );
            }


            OOXMLPackageWriter writer =
                    new OOXMLPackageWriter();

            writer.write(
                    packageData,
                    output
            );


            if (!Files.exists(output) ||
                    Files.size(output) == 0) {

                throw new AssertionError(
                        "Sanitized XLSX was not created."
                );
            }


            OOXMLPackage sanitized =
                    reader.read(
                            output
                    );


            if (sanitized.hasPart(
                    "xl/vbaProject.bin"
            )) {

                throw new AssertionError(
                        "VBA project exists in sanitized output."
                );
            }


            System.out.println();

            System.out.println(
                    "XLSX THREAT SANITIZER TEST PASSED"
            );

            System.out.println(
                    "Output : " +
                    output
            );

        } catch (Exception e) {

            System.err.println();

            System.err.println(
                    "XLSX THREAT SANITIZER TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}