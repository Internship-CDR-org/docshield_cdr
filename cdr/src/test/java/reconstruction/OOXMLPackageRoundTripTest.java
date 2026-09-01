package reconstruction;

import model.ooxml.OOXMLPackage;
import parsing.ooxml.OOXMLPackageReader;

import java.nio.file.Files;
import java.nio.file.Path;

public class OOXMLPackagePPTXRoundTripTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java reconstruction.OOXMLPackageRoundTripTest <file>"
            );

            System.exit(1);
        }


        Path input =
                Path.of(args[0]);


        String fileName =
                input.getFileName()
                        .toString();


        int extensionIndex =
                fileName.lastIndexOf('.');


        String baseName =
                extensionIndex > 0
                        ? fileName.substring(
                                0,
                                extensionIndex
                        )
                        : fileName;


        String extension =
                extensionIndex > 0
                        ? fileName.substring(
                                extensionIndex
                        )
                        : "";


        Path output =
                Path.of(
                        "output",
                        "reconstructed",
                        baseName +
                        "_roundtrip" +
                        extension
                );


        try {

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();


            OOXMLPackage original =
                    reader.read(input);


            System.out.println(
                    "Original parts         : " +
                    original.getPartCount()
            );

            System.out.println(
                    "Original relationships : " +
                    original.getRelationshipCount()
            );


            OOXMLPackageWriter writer =
                    new OOXMLPackageWriter();


            writer.write(
                    original,
                    output
            );


            OOXMLPackage roundTrip =
                    reader.read(output);


            boolean partsMatch =
                    original.getPartCount() ==
                    roundTrip.getPartCount();


            boolean relationshipsMatch =
                    original.getRelationshipCount() ==
                    roundTrip.getRelationshipCount();


            System.out.println(
                    "Round-trip parts       : " +
                    roundTrip.getPartCount()
            );

            System.out.println(
                    "Round-trip relationships: " +
                    roundTrip.getRelationshipCount()
            );

            System.out.println(
                    "Parts preserved        : " +
                    partsMatch
            );

            System.out.println(
                    "Relationships preserved: " +
                    relationshipsMatch
            );


            if (!partsMatch ||
                    !relationshipsMatch) {

                throw new IllegalStateException(
                        "OOXML round-trip structure changed."
                );
            }


            if (!Files.exists(output) ||
                    Files.size(output) == 0) {

                throw new IllegalStateException(
                        "Round-trip output was not created."
                );
            }


            System.out.println();
            System.out.println(
                    "OOXML ROUND-TRIP TEST PASSED"
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "OOXML ROUND-TRIP TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}