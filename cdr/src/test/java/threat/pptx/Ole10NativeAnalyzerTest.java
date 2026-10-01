package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import parsing.ooxml.OOXMLPackageReader;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.ByteArrayInputStream;
import java.util.List;


/**
 * Test for Ole10NativeAnalyzer.
 *
 * This test only reads the Ole10Native stream.
 * It never executes the embedded native payload.
 */
public class Ole10NativeAnalyzerTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java threat.Ole10NativeAnalyzerTest <file.pptx>"
            );

            System.exit(1);
        }


        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "       OLE10NATIVE ANALYZER TEST"
            );

            System.out.println(
                    "=============================================="
            );


            // =================================================
            // READ PPTX
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage packageData =
                    reader.read(args[0]);


            System.out.println(
                    "Package parts : " +
                    packageData.getPartCount()
            );


            Ole10NativeAnalyzer analyzer =
                    new Ole10NativeAnalyzer();


            int oleCount = 0;
            int nativeCount = 0;


            // =================================================
            // FIND OLE OBJECTS
            // =================================================

            for (OOXMLPart part :
                    packageData.getParts()) {

                if (part == null) {
                    continue;
                }


                String name =
                        part.getPartName();

                String type =
                        part.getContentType();


                boolean possibleOle =
                        (name != null &&
                                name.toLowerCase()
                                        .contains("/embeddings/"))
                        ||
                        (type != null &&
                                type.toLowerCase()
                                        .contains("oleobject"));


                if (!possibleOle) {
                    continue;
                }


                oleCount++;


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
                        "OLE part : " +
                        name
                );

                System.out.println(
                        "Size     : " +
                        data.length +
                        " bytes"
                );


                // =================================================
                // OPEN OLE
                // =================================================

                try (
                        POIFSFileSystem fs =
                                new POIFSFileSystem(
                                        new ByteArrayInputStream(data)
                                )
                ) {

                    DirectoryNode root =
                            fs.getRoot();


                    List<
                            Ole10NativeAnalyzer.NativePayload
                            > results =
                            analyzer.inspect(root);


                    System.out.println(
                            "Ole10Native streams : " +
                            results.size()
                    );


                    // =================================================
                    // DISPLAY METADATA
                    // =================================================

                    for (
                            Ole10NativeAnalyzer.NativePayload
                                    payload :
                            results
                    ) {

                        nativeCount++;


                        System.out.println();

                        System.out.println(
                                "Native payload found"
                        );

                        System.out.println(
                                "Label          : " +
                                safe(payload.getLabel())
                        );

                        System.out.println(
                                "Filename       : " +
                                safe(payload.getFilename())
                        );

                        System.out.println(
                                "Source path    : " +
                                safe(payload.getSourcePath())
                        );

                        System.out.println(
                                "Temporary path : " +
                                safe(payload.getTemporaryPath())
                        );


                        byte[] nativeData =
                                payload.getPayload();


                        System.out.println(
                                "Payload bytes  : " +
                                (
                                    nativeData == null
                                        ? 0
                                        : nativeData.length
                                )
                        );

                        if (nativeData != null) {

                        String preview =
                                new String(
                                        nativeData,
                                        java.nio.charset.StandardCharsets.ISO_8859_1
                                );

                        System.out.println(
                                "Payload preview:"
                        );

                        System.out.println(
                                preview
                        );
                    }
                    }


                } catch (Exception e) {

                    System.out.println(
                            "Unable to inspect OLE part: " +
                            e.getMessage()
                    );
                }
            }


            // =================================================
            // SUMMARY
            // =================================================

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "OLE objects inspected : " +
                    oleCount
            );

            System.out.println(
                    "Ole10Native found     : " +
                    nativeCount
            );

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "OLE10NATIVE ANALYSIS COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "OLE10NATIVE ANALYSIS FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }


    private static String safe(
            String value) {

        if (value == null ||
                value.isEmpty()) {

            return "(none)";
        }

        return value;
    }
}