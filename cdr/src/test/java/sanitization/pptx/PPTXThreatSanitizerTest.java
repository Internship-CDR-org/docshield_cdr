package sanitization.pptx;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import parsing.ooxml.OOXMLPackageReader;
import parsing.pptx.PPTXRelationshipGraph;

import threat.common.SecurityFinding;
import threat.pptx.Ole10NativeAnalyzer;
import threat.pptx.PayloadFingerprint;
import threat.pptx.PayloadIdentifier;
import threat.pptx.SecurityPolicy;

import reconstruction.OOXMLPackageWriter;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;


/**
 * End-to-end test for PPTX active-content sanitization.
 *
 * Pipeline:
 *
 *     PPTX
 *       ↓
 *     Reader
 *       ↓
 *     Package
 *       ↓
 *     Ole10Native inspection
 *       ↓
 *     Payload identification
 *       ↓
 *     Payload fingerprinting
 *       ↓
 *     Security policy
 *       ↓
 *     Sanitizer
 *       ↓
 *     Writer
 *       ↓
 *     Sanitized PPTX
 */
public class PPTXThreatSanitizerTest {


    public static void main(
            String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java sanitization.pptx.PPTXThreatSanitizerTest <file.pptx>"
            );

            System.exit(1);
        }


        Path input =
                Path.of(args[0]);


        Path output =
                Path.of(
                        "output",
                        "reconstructed",
                        "sanitized-test.pptx"
                );


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       PPTX THREAT SANITIZER TEST"
            );

            System.out.println(
                    "=============================================="
            );


            // =================================================
            // READ PACKAGE
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();


            OOXMLPackage pptxPackage =
                    reader.read(input);


            System.out.println();
            System.out.println(
                    "Original package parts : "
                    + pptxPackage.getPartCount()
            );

            System.out.println(
                    "Original relationships : "
                    + pptxPackage.getRelationshipCount()
            );


            // =================================================
            // FIND EMBEDDED PARTS
            // =================================================

            List<OOXMLPart> embeddedParts =
                    new ArrayList<>();


            for (OOXMLPart part :
                    pptxPackage.getParts()) {

                if (part == null ||
                        part.getPartName() == null) {

                    continue;
                }


                String name =
                        part.getPartName()
                                .toLowerCase();


                if (name.startsWith(
                        "ppt/embeddings/"
                )) {

                    embeddedParts.add(
                            part
                    );
                }
            }


            System.out.println();
            System.out.println(
                    "Embedded parts found : "
                    + embeddedParts.size()
            );


            // =================================================
            // ANALYZE OLE10NATIVE PAYLOADS
            // =================================================

            List<SecurityFinding> findings =
                    new ArrayList<>();


            Ole10NativeAnalyzer nativeAnalyzer =
                    new Ole10NativeAnalyzer();


            PayloadIdentifier identifier =
                    new PayloadIdentifier();


            PayloadFingerprint fingerprint =
                    new PayloadFingerprint();


            SecurityPolicy policy =
                    new SecurityPolicy();


            for (OOXMLPart part :
                    embeddedParts) {

                byte[] data =
                        part.getData();


                if (data == null ||
                        data.length == 0) {

                    continue;
                }


                System.out.println();
                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "OLE part : "
                        + part.getPartName()
                );

                System.out.println(
                        "Size     : "
                        + data.length
                        + " bytes"
                );


                /*
                 * Open the OLE Compound File using Apache POI.
                 *
                 * The native analyzer operates on DirectoryNode,
                 * not directly on OOXMLPart.
                 */
                try (
                        POIFSFileSystem fs =
                                new POIFSFileSystem(
                                        new ByteArrayInputStream(
                                                data
                                        )
                                )
                ) {

                    DirectoryNode root =
                            fs.getRoot();


                    List<
                            Ole10NativeAnalyzer.NativePayload
                            > payloads =
                            nativeAnalyzer.inspect(
                                    root
                            );


                    System.out.println(
                            "Ole10Native streams : "
                            + payloads.size()
                    );


                    for (
                            Ole10NativeAnalyzer.NativePayload payload :
                            payloads) {

                        if (payload == null) {
                            continue;
                        }


                        byte[] payloadBytes =
                                payload.getPayload();


                        String filename =
                                payload.getFilename();


                        if (filename == null ||
                                filename.isBlank()) {

                            filename =
                                    payload.getLabel();
                        }


                        System.out.println();
                        System.out.println(
                                "Native payload : "
                                + filename
                        );


                        // -----------------------------------------
                        // IDENTIFICATION
                        // -----------------------------------------

                        PayloadIdentifier.Identification identification =
                                identifier.identify(
                                        filename,
                                        payloadBytes
                                );


                        // -----------------------------------------
                        // FINGERPRINT
                        // -----------------------------------------

                        PayloadFingerprint.Fingerprint
                                payloadFingerprint =
                                fingerprint.fingerprint(
                                        payloadBytes
                                );


                        System.out.println(
                                "Payload type : "
                                + identification.getType()
                        );


                        System.out.println(
                                "Extension    : "
                                + identification.getExtension()
                        );


                        System.out.println(
                                "Payload size : "
                                + payloadFingerprint.getSize()
                        );


                        System.out.println(
                                "SHA-256      : "
                                + payloadFingerprint.getSha256()
                        );


                        // -----------------------------------------
                        // SECURITY POLICY
                        // -----------------------------------------

                        findings.addAll(
                                policy.evaluate(
                                        identification,
                                        payloadFingerprint,
                                        part
                                )
                        );
                    }
                }
            }


            // =================================================
            // SHOW FINDINGS
            // =================================================

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "SECURITY FINDINGS"
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Findings : "
                    + findings.size()
            );


            for (SecurityFinding finding :
                    findings) {

                System.out.println();
                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "Part           : "
                        + finding.getPartName()
                );

                System.out.println(
                        "Classification : "
                        + finding.getClassification()
                );

                System.out.println(
                        "Type           : "
                        + finding.getType()
                );

                System.out.println(
                        "Severity       : "
                        + finding.getSeverity()
                );

                System.out.println(
                        "Evidence       : "
                        + finding.getEvidence()
                );

                System.out.println(
                        "Action         : "
                        + finding.getRecommendedAction()
                );
            }


            // =================================================
            // SANITIZE
            // =================================================

            PPTXThreatSanitizer sanitizer =
                    new PPTXThreatSanitizer();


            List<String> actions =
                    sanitizer.sanitize(
                            pptxPackage,
                            findings
                    );


            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "SANITIZATION"
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Actions : "
                    + actions.size()
            );


            for (String action :
                    actions) {

                System.out.println(
                        "  - " + action
                );
            }


            // =================================================
            // VERIFY IN-MEMORY PACKAGE
            // =================================================

            System.out.println();
            System.out.println(
                    "========== AFTER SANITIZATION =========="
            );


            System.out.println(
                    "Package parts : "
                    + pptxPackage.getPartCount()
            );

            System.out.println(
                    "Relationships : "
                    + pptxPackage.getRelationshipCount()
            );


            boolean oleStillPresent =
                    pptxPackage.hasPart(
                            "ppt/embeddings/oleObject1.bin"
                    );


            System.out.println(
                    "OLE part still present : "
                    + oleStillPresent
            );


            boolean rId2StillPresent =
                    false;


            for (OOXMLRelationship relationship :
                    pptxPackage.getRelationships()) {

                if (relationship == null) {
                    continue;
                }


                if ("rId2".equals(
                        relationship.getId()
                )) {

                    rId2StillPresent =
                            true;

                    break;
                }
            }


            System.out.println(
                    "rId2 still present    : "
                    + rId2StillPresent
            );


            // =================================================
            // WRITE SANITIZED PACKAGE
            // =================================================

            OOXMLPackageWriter writer =
                    new OOXMLPackageWriter();


            writer.write(
                    pptxPackage,
                    output
            );


            System.out.println();
            System.out.println(
                    "Sanitized file : "
                    + output
            );


            System.out.println(
                    "File exists    : "
                    + Files.exists(output)
            );


            if (Files.exists(output)) {

                System.out.println(
                        "File size      : "
                        + Files.size(output)
                        + " bytes"
                );
            }


            // =================================================
            // RE-READ SANITIZED PACKAGE
            // =================================================

            OOXMLPackage sanitizedPackage =
                    reader.read(output);


            System.out.println();
            System.out.println(
                    "========== RE-READ SANITIZED PACKAGE =========="
            );


            System.out.println(
                    "Parts         : "
                    + sanitizedPackage.getPartCount()
            );

            System.out.println(
                    "Relationships : "
                    + sanitizedPackage.getRelationshipCount()
            );


            System.out.println(
                    "OLE part exists : "
                    + sanitizedPackage.hasPart(
                            "ppt/embeddings/oleObject1.bin"
                    )
            );


            PPTXRelationshipGraph graph =
                    new PPTXRelationshipGraph(
                            sanitizedPackage
                    );


            System.out.println(
                    "Graph edges     : "
                    + graph.getEdgeCount()
            );


            // =================================================
            // COMPLETE
            // =================================================

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       SANITIZATION TEST COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "SANITIZATION TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}