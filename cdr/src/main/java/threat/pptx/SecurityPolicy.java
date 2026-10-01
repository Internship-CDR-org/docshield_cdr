package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPart;

import java.util.ArrayList;
import java.util.List;

/**
 * Universal CDR security policy.
 *
 * This class evaluates identified payloads and decides
 * whether they violate the security policy.
 *
 * It does not know anything about PPTX/OLE internals.
 */
public class SecurityPolicy {

    public List<SecurityFinding> evaluate(
            PayloadIdentifier.Identification identification,
            PayloadFingerprint.Fingerprint fingerprint,
            OOXMLPart part) {

        List<SecurityFinding> findings =
                new ArrayList<>();

        if (identification == null ||
                fingerprint == null) {

            return findings;
        }


        PayloadType type =
                identification.getType();


        /*
         * Active native/script content embedded inside
         * a document is unsafe to preserve blindly
         * during CDR reconstruction.
         */
        if (isActiveContent(type)) {

            String filename =
                    identification.getFilename();


            String evidence =
                    "Embedded payload: "
                    + filename
                    + ", type: "
                    + type
                    + ", size: "
                    + fingerprint.getSize()
                    + " bytes"
                    + ", SHA-256: "
                    + fingerprint.getSha256();


            SecurityFinding finding =
                    new SecurityFinding(
                            FindingClassification.THREAT,

                            ThreatType.EMBEDDED_ACTIVE_CONTENT,

                            ThreatSeverity.HIGH,

                            part,

                            part == null
                                    ? null
                                    : part.getPartName(),

                            null,

                            evidence,

                            "Active executable or script "
                            + "content was embedded inside "
                            + "the document.",

                            "Remove or replace the embedded "
                            + "active payload during "
                            + "reconstruction."
                    );


            findings.add(finding);
        }


        return findings;
    }


    private boolean isActiveContent(
            PayloadType type) {

        if (type == null) {
            return false;
        }


        switch (type) {

            case WINDOWS_BATCH_SCRIPT:
            case WINDOWS_COMMAND_SCRIPT:
            case POWERSHELL_SCRIPT:
            case JAVASCRIPT:
            case VBS_SCRIPT:
            case VBA_SOURCE:
            case PE_EXECUTABLE:
            case ELF_EXECUTABLE:

                return true;


            default:

                return false;
        }
    }
}