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


public class PayloadFingerprintTest {

    public static void main(
            String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.PayloadFingerprintTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       PAYLOAD FINGERPRINT TEST"
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

            PayloadFingerprint fingerprint =
                    new PayloadFingerprint();


            int payloadCount = 0;


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
                            > payloads =
                            oleAnalyzer.inspect(
                                    root
                            );


                    for (
                            Ole10NativeAnalyzer.NativePayload
                                    payload :
                            payloads
                    ) {

                        payloadCount++;


                        PayloadFingerprint.Fingerprint
                                result =
                                fingerprint.fingerprint(
                                        payload.getPayload()
                                );


                        System.out.println();

                        System.out.println(
                                "----------------------------------------------"
                        );

                        System.out.println(
                                "Filename    : " +
                                payload.getFilename()
                        );

                        System.out.println(
                                "Payload size: " +
                                result.getSize() +
                                " bytes"
                        );

                        System.out.println(
                                "SHA-256     : " +
                                result.getSha256()
                        );
                    }
                }
            }


            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Payloads fingerprinted : " +
                    payloadCount
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "PAYLOAD FINGERPRINT COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println(
                    "PAYLOAD FINGERPRINT FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}