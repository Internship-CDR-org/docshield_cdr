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


public class PayloadIdentifierTest {

    public static void main(
            String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.PayloadIdentifierTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       PAYLOAD IDENTIFIER TEST"
            );

            System.out.println(
                    "=============================================="
            );


            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pkg =
                    reader.read(args[0]);


            Ole10NativeAnalyzer oleAnalyzer =
                    new Ole10NativeAnalyzer();

            PayloadIdentifier identifier =
                    new PayloadIdentifier();


            int payloads = 0;


            for (OOXMLPart part :
                    pkg.getParts()) {

                if (part == null ||
                        part.getPartName() == null) {
                    continue;
                }


                if (!part.getPartName()
                        .toLowerCase()
                        .contains("/embeddings/")) {
                    continue;
                }


                byte[] oleData =
                        part.getData();


                if (oleData == null) {
                    continue;
                }


                /*
                 * Open the OLE container.
                 */
                try (
                        org.apache.poi.poifs.filesystem
                                .POIFSFileSystem fs =
                                new org.apache.poi.poifs.filesystem
                                        .POIFSFileSystem(
                                                new java.io.ByteArrayInputStream(
                                                        oleData
                                                )
                                        )
                ) {

                    org.apache.poi.poifs.filesystem
                            .DirectoryNode root =
                            fs.getRoot();


                    List<
                            Ole10NativeAnalyzer.NativePayload
                            > nativePayloads =
                            oleAnalyzer.inspect(
                                    root
                            );


                    for (
                            Ole10NativeAnalyzer.NativePayload
                                    nativePayload :
                            nativePayloads
                    ) {

                        payloads++;


                        PayloadIdentifier.Identification
                                identification =
                                identifier.identify(
                                        nativePayload
                                                .getFilename(),
                                        nativePayload
                                                .getPayload()
                                );


                        System.out.println();

                        System.out.println(
                                "----------------------------------------------"
                        );

                        System.out.println(
                                "Filename    : " +
                                nativePayload.getFilename()
                        );

                        System.out.println(
                                "Extension   : " +
                                identification
                                        .getExtension()
                        );

                        System.out.println(
                                "Payload     : " +
                                (
                                        nativePayload
                                                .getPayload()
                                                == null
                                                ? 0
                                                : nativePayload
                                                        .getPayload()
                                                        .length
                                ) +
                                " bytes"
                        );

                        System.out.println(
                                "Type        : " +
                                identification.getType()
                        );

                        System.out.println(
                                "Evidence    : " +
                                identification.getEvidence()
                        );
                    }
                }
            }


            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Payloads identified : " +
                    payloads
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "PAYLOAD IDENTIFICATION COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println(
                    "PAYLOAD IDENTIFICATION FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}