package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import java.util.ArrayList;
import java.util.List;


/**
 * Inspects embedded objects contained inside a package.
 *
 * This analyzer performs discovery and basic binary identification.
 *
 * It does NOT execute embedded content.
 * It does NOT modify the package.
 */
public class EmbeddedObjectAnalyzer
        implements SecurityAnalyzer<OOXMLPackage> {


    // OLE Compound File / Structured Storage signature.
    private static final byte[] OLE_SIGNATURE = {
            (byte) 0xD0,
            (byte) 0xCF,
            (byte) 0x11,
            (byte) 0xE0,
            (byte) 0xA1,
            (byte) 0xB1,
            (byte) 0x1A,
            (byte) 0xE1
    };


    @Override
    public List<SecurityFinding> analyze(
            OOXMLPackage packageData) {

        List<SecurityFinding> findings =
                new ArrayList<>();


        if (packageData == null) {
            return findings;
        }


        for (OOXMLPart part :
                packageData.getParts()) {

            if (part == null) {
                continue;
            }


            if (!looksLikeEmbeddedObject(part)) {
                continue;
            }


            byte[] data =
                    part.getData();


            if (data == null ||
                    data.length == 0) {

                findings.add(
                        createFinding(
                                part,
                                ThreatSeverity.MEDIUM,
                                "Embedded object has no readable data.",
                                "The package identifies a possible embedded object, but its content could not be inspected.",
                                "Investigate the package part before reconstruction."
                        )
                );

                continue;
            }


            // =================================================
            // OLE COMPOUND FILE
            // =================================================

            if (hasOleSignature(data)) {

                findings.add(
                        createFinding(
                                part,
                                ThreatSeverity.MEDIUM,
                                "OLE Compound File signature detected.",
                                "The embedded resource contains an OLE Compound File structure.",
                                "Perform deeper OLE stream inspection before reconstruction."
                        )
                );

                continue;
            }


            // =================================================
            // UNKNOWN EMBEDDED OBJECT
            // =================================================

            findings.add(
                    new SecurityFinding(
                            FindingClassification.OBSERVATION,
                            ThreatType.EMBEDDED_OBJECT,
                            ThreatSeverity.INFO,
                            part,
                            null,
                            null,
                            "Embedded resource: " +
                                    part.getPartName() +
                                    ", content type: " +
                                    part.getContentType() +
                                    ", size: " +
                                    data.length +
                                    " bytes.",
                            "An embedded package resource was discovered.",
                            "Route the object to the appropriate embedded-content analyzer."
                    )
            );
        }


        return findings;
    }


    // =========================================================
    // EMBEDDED OBJECT IDENTIFICATION
    // =========================================================

    private boolean looksLikeEmbeddedObject(
            OOXMLPart part) {

        String name =
                part.getPartName();

        String contentType =
                part.getContentType();


        String normalizedName =
                name == null
                        ? ""
                        : name.toLowerCase();


        String normalizedType =
                contentType == null
                        ? ""
                        : contentType.toLowerCase();


        /*
         * PPTX commonly stores embedded objects under
         * ppt/embeddings/.
         */
        if (normalizedName.contains(
                "/embeddings/")) {

            return true;
        }


        /*
         * Recognize common OLE content types without treating
         * every generic "package" content type as OLE.
         */
        if (normalizedType.contains(
                "oleobject")) {

            return true;
        }


        if (normalizedType.equals(
                "application/vnd.ms-office.oleObject")) {

            return true;
        }


        return false;
    }


    // =========================================================
    // OLE SIGNATURE
    // =========================================================

    private boolean hasOleSignature(
            byte[] data) {

        if (data.length <
                OLE_SIGNATURE.length) {

            return false;
        }


        for (int i = 0;
             i < OLE_SIGNATURE.length;
             i++) {

            if (data[i] !=
                    OLE_SIGNATURE[i]) {

                return false;
            }
        }


        return true;
    }


    // =========================================================
    // CREATE FINDING
    // =========================================================

    private SecurityFinding createFinding(
            OOXMLPart part,
            ThreatSeverity severity,
            String evidence,
            String description,
            String action) {

        return new SecurityFinding(
                FindingClassification.SUSPICIOUS,
                ThreatType.OLE_OBJECT,
                severity,
                part,
                null,
                null,
                evidence,
                description,
                action
        );
    }
}