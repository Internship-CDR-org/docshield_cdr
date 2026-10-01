package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import parsing.ooxml.OOXMLPackageReader;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

public class SecurityPolicyTest {

    public static void main(
            String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.SecurityPolicyTest <file>"
            );

            System.exit(1);
        }


        try {

            System.out.println();

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       SECURITY POLICY TEST"
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

            PayloadFingerprint fingerprint =
                    new PayloadFingerprint();

            SecurityPolicy policy =
                    new SecurityPolicy();


            int payloadCount = 0;

            int findingCount = 0;


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
                        POIFSFileSystem fs =
                                new POIFSFileSystem(
                                        new ByteArrayInputStream(
                                                oleData
                                        )
                                )
                ) {

                    DirectoryNode root =
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


                        PayloadIdentifier.Identification
                                identification =
                                identifier.identify(
                                        payload.getFilename(),
                                        payload.getPayload()
                                );


                        PayloadFingerprint.Fingerprint
                                fp =
                                fingerprint.fingerprint(
                                        payload.getPayload()
                                );


                            List<SecurityFinding>
                                    findings =
                                    policy.evaluate(
                                            identification,
                                            fp,
                                            part
                                    );


                        for (
                                SecurityFinding finding :
                                findings
                        ) {

                            findingCount++;


                            System.out.println();

                            System.out.println(
                                    "----------------------------------------------"
                            );

                            System.out.println(
                                    "Source       : " +
                                    finding.getSourcePart()
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
                                    "Evidence     : " +
                                    finding.getEvidence()
                            );

                            System.out.println(
                                    "Description  : " +
                                    finding.getDescription()
                            );
                        }
                    }
                }
            }


            System.out.println();

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Payloads evaluated : " +
                    payloadCount
            );

            System.out.println(
                    "Threat findings    : " +
                    findingCount
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "SECURITY POLICY TEST COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println(
                    "SECURITY POLICY TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}