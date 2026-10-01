package reconstruction;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;

import java.nio.file.Path;


/**
 * Tests the new package-level PPTX round-trip.
 *
 * Original PPTX
 *      ↓
 * OOXMLPackageReader
 *      ↓
 * OOXMLPackage
 *      ↓
 * OOXMLPackageWriter
 *      ↓
 * Round-trip PPTX
 */
public class OOXMLPackagePPTXRoundTripTest {

    public static void main(
            String[] args) {

        if (args.length != 2) {

            System.err.println(
                    "Usage:"
            );

            System.err.println(
                    "java reconstruction.OOXMLPackageRoundTripTest " +
                    "<input.pptx> <output.pptx>"
            );

            System.exit(1);
        }


        Path input =
                Path.of(
                        args[0]
                );


        Path output =
                Path.of(
                        args[1]
                );


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "       PPTX PACKAGE ROUND-TRIP TEST"
            );
            System.out.println(
                    "=============================================="
            );


            // -------------------------------------------------
            // READ
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "Reading package..."
            );


            OOXMLPackageReader reader =
                    new OOXMLPackageReader();


            OOXMLPackage pptxPackage =
                    reader.read(
                            input
                    );


            System.out.println(
                    "Parts          : " +
                    pptxPackage.getPartCount()
            );


            System.out.println(
                    "Relationships   : " +
                    pptxPackage.getRelationshipCount()
            );


            System.out.println(
                    "Content types  : " +
                    pptxPackage
                            .getContentTypes()
                            .size()
            );


            // -------------------------------------------------
            // WRITE
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "Writing package..."
            );


            OOXMLPackageWriter writer =
                    new OOXMLPackageWriter();


            writer.write(
                    pptxPackage,
                    output
            );


            System.out.println(
                    "Output          : " +
                    output
            );


            // -------------------------------------------------
            // COMPLETE
            // -------------------------------------------------

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "ROUND-TRIP COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "ROUND-TRIP FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}