package sanitization.docx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import parsing.ooxml.OOXMLPackageReader;
import reconstruction.OOXMLPackageWriter;

import threat.common.SecurityFinding;
import threat.docx.DOCXThreatAnalyzer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class DOCXThreatSanitizerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java sanitization.docx.DOCXThreatSanitizerTest <file.docx>"
            );

            System.exit(1);
        }

        Path input =
                Path.of(args[0]);

        Path output =
                Path.of(
                        "output",
                        "reconstructed",
                        "docx_vba_sanitized.docx"
                );

        try {

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage packageData =
                    reader.read(input);


            DOCXThreatAnalyzer analyzer =
                    new DOCXThreatAnalyzer();

            List<SecurityFinding> findings =
                    analyzer.analyze(
                            packageData
                    );


            System.out.println(
                    "Threat findings : " +
                    findings.size()
            );


            DOCXThreatSanitizer sanitizer =
                    new DOCXThreatSanitizer();

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
                        "  - " + action
                );
            }


            if (packageData.hasPart(
                    "word/vbaProject.bin"
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
                        "Sanitized DOCX was not created."
                );
            }


            OOXMLPackage sanitized =
                    reader.read(output);


            if (sanitized.hasPart(
                    "word/vbaProject.bin"
            )) {

                throw new AssertionError(
                        "VBA project exists in sanitized output."
                );
            }


            System.out.println();
            System.out.println(
                    "DOCX THREAT SANITIZER TEST PASSED"
            );

            System.out.println(
                    "Output : " +
                    output
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "DOCX THREAT SANITIZER TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}