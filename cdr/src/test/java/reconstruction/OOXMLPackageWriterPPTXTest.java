package reconstruction;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;

import java.nio.file.Files;
import java.nio.file.Path;

public class OOXMLPackageWriterPPTXTest {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println(
                    "Usage: java reconstruction.OOXMLPackageWriterTest <file.pptx>"
            );
            System.exit(1);
        }

        Path input =
                Path.of(args[0]);

        Path output =
                Path.of(
                        "output/reconstructed/",
                        input.getFileName()
                                .toString()
                                .replace(
                                        ".pptx",
                                        "_roundtrip.pptx"
                                )
                );

        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "          PPTX PACKAGE ROUND-TRIP"
            );
            System.out.println(
                    "=============================================="
            );

            // -------------------------------------------------
            // READ
            // -------------------------------------------------

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage original =
                    reader.read(input);

            System.out.println();
            System.out.println(
                    "Original parts         : "
                            + original.getPartCount()
            );

            System.out.println(
                    "Original relationships  : "
                            + original.getRelationshipCount()
            );

            // -------------------------------------------------
            // WRITE
            // -------------------------------------------------

            OOXMLPackageWriter writer =
                    new OOXMLPackageWriter();

            writer.write(
                    original,
                    output
            );

            System.out.println();
            System.out.println(
                    "Round-trip file        : "
                            + output
            );

            System.out.println(
                    "File exists             : "
                            + Files.exists(output)
            );

            System.out.println(
                    "File size               : "
                            + Files.size(output)
                            + " bytes"
            );

            // -------------------------------------------------
            // READ AGAIN
            // -------------------------------------------------

            OOXMLPackage roundTrip =
                    reader.read(output);

            System.out.println();
            System.out.println(
                    "Round-trip parts       : "
                            + roundTrip.getPartCount()
            );

            System.out.println(
                    "Round-trip relationships: "
                            + roundTrip.getRelationshipCount()
            );

            // -------------------------------------------------
            // VALIDATION
            // -------------------------------------------------

            boolean partsMatch =
                    original.getPartCount()
                            == roundTrip.getPartCount();

            boolean relationshipsMatch =
                    original.getRelationshipCount()
                            == roundTrip.getRelationshipCount();

            System.out.println();

            System.out.println(
                    "Parts preserved        : "
                            + partsMatch
            );

            System.out.println(
                    "Relationships preserved: "
                            + relationshipsMatch
            );

            if (!partsMatch ||
                    !relationshipsMatch) {

                throw new IllegalStateException(
                        "Round-trip package structure changed."
                );
            }

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "          ROUND-TRIP TEST PASSED"
            );
            System.out.println(
                    "=============================================="
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "ROUND-TRIP TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}
