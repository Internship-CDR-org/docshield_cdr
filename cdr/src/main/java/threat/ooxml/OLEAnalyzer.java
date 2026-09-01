package threat.ooxml;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;


/**
 * Performs structural inspection of OLE Compound Files
 * contained inside a document package.
 *
 * This analyzer only reads data.
 * It never executes embedded content.
 */
public class OLEAnalyzer
        implements SecurityAnalyzer<OOXMLPackage> {

    @Override
    public List<SecurityFinding> analyze(
            OOXMLPackage packageData) {

        List<SecurityFinding> findings =
                new ArrayList<>();

        if (packageData == null) {
            return findings;
        }

        for (OOXMLPart part : packageData.getParts()) {

            if (part == null) {
                continue;
            }

            if (!looksLikeOLE(part)) {
                continue;
            }

            byte[] data = part.getData();

            if (data == null || data.length == 0) {

                findings.add(
                        createFinding(
                                part,
                                FindingClassification.SUSPICIOUS,
                                ThreatSeverity.MEDIUM,
                                ThreatType.OLE_OBJECT,
                                "OLE resource contains no readable data.",
                                "Inspect the package part before reconstruction."
                        )
                );

                continue;
            }

            try (
                    POIFSFileSystem fs =
                            new POIFSFileSystem(
                                    new ByteArrayInputStream(data)
                            )
            ) {

                DirectoryNode root =
                        fs.getRoot();

                int[] counts =
                        inspectDirectory(
                                root,
                                findings,
                                part,
                                ""
                        );

                int storageCount = counts[0];
                int streamCount = counts[1];

                String evidence =
                        "OLE resource: " +
                        part.getPartName() +
                        ", size: " +
                        data.length +
                        " bytes, storages: " +
                        storageCount +
                        ", streams: " +
                        streamCount;

                findings.add(
                        new SecurityFinding(
                                FindingClassification.OBSERVATION,
                                ThreatType.OLE_OBJECT,
                                ThreatSeverity.INFO,
                                part,
                                null,
                                null,
                                evidence,
                                "A valid OLE Compound File structure was detected.",
                                "Perform stream-level inspection before reconstruction."
                        )
                );

            } catch (Exception e) {

                findings.add(
                        createFinding(
                                part,
                                FindingClassification.SUSPICIOUS,
                                ThreatSeverity.HIGH,
                                ThreatType.OLE_OBJECT,
                                "The package part appears to be an OLE object but could not be parsed as a valid Compound File: "
                                        + e.getMessage(),
                                "Quarantine the embedded object and investigate it before reconstruction."
                        )
                );
            }
        }

        return findings;
    }


    // =========================================================
    // RECURSIVE OLE DIRECTORY INSPECTION
    // =========================================================

    private int[] inspectDirectory(
            DirectoryNode directory,
            List<SecurityFinding> findings,
            OOXMLPart part,
            String parentPath) {

        int storageCount = 0;
        int streamCount = 0;

        for (Entry entry : directory) {

            if (entry == null) {
                continue;
            }

            String name = entry.getName();

            String currentPath =
                    parentPath.isEmpty()
                            ? name
                            : parentPath + "/" + name;


            // =================================================
            // STORAGE
            // =================================================

            if (entry instanceof DirectoryNode) {

                storageCount++;

                DirectoryNode child =
                        (DirectoryNode) entry;

                int[] childCounts =
                        inspectDirectory(
                                child,
                                findings,
                                part,
                                currentPath
                        );

                storageCount += childCounts[0];
                streamCount += childCounts[1];

                findings.add(
                        new SecurityFinding(
                                FindingClassification.OBSERVATION,
                                ThreatType.OLE_OBJECT,
                                ThreatSeverity.INFO,
                                part,
                                null,
                                null,
                                "OLE storage: " + currentPath,
                                "An OLE storage directory was discovered.",
                                "Inspect contained streams if required."
                        )
                );

            }

            // =================================================
            // STREAM
            // =================================================

            else {

                streamCount++;

                long size = -1;

                if (entry instanceof DocumentEntry) {

                    size =
                            ((DocumentEntry) entry)
                                    .getSize();
                }

                ThreatType streamType = determineStreamType(name);
                boolean macroStream = streamType == ThreatType.VBA_PROJECT ||
                        currentPath.toLowerCase().contains("_vba_project");
                findings.add(
                        new SecurityFinding(
                                macroStream ? FindingClassification.THREAT : FindingClassification.OBSERVATION,
                                streamType,
                                macroStream ? ThreatSeverity.CRITICAL : ThreatSeverity.INFO,
                                part,
                                null,
                                null,
                                "OLE stream: " + currentPath + ", size: " + size + " bytes",
                                macroStream
                                        ? "The embedded OLE Compound File contains VBA project storage/stream content."
                                        : "An internal OLE stream was discovered.",
                                macroStream
                                        ? "Remove the containing OLE object during CDR."
                                        : "Route potentially relevant streams to a specialized analyzer."
                        )
                );
            }
        }

        return new int[] {
                storageCount,
                streamCount
        };
    }


    // =========================================================
    // STREAM CLASSIFICATION
    // =========================================================

    private ThreatType determineStreamType(
            String streamName) {

        if (streamName == null) {
            return ThreatType.OLE_OBJECT;
        }

        String normalized =
                streamName.toLowerCase();

        if (normalized.contains("vba")) {
            return ThreatType.VBA_PROJECT;
        }

        if (normalized.equals("dir")) {
            return ThreatType.VBA_PROJECT;
        }

        if (normalized.contains("package")) {
            return ThreatType.EMBEDDED_OBJECT;
        }

        if (normalized.contains("ole")) {
            return ThreatType.OLE_OBJECT;
        }

        if (normalized.contains("compobj")) {
            return ThreatType.OLE_OBJECT;
        }

        return ThreatType.OLE_OBJECT;
    }


    // =========================================================
    // OLE IDENTIFICATION
    // =========================================================

    private boolean looksLikeOLE(
            OOXMLPart part) {

        String name =
                part.getPartName();

        String type =
                part.getContentType();

        String normalizedName =
                name == null
                        ? ""
                        : name.toLowerCase();

        String normalizedType =
                type == null
                        ? ""
                        : type.toLowerCase();

        // Only treat the part as an OLE candidate when its content type or
        // binary signature says it is OLE. A generic /embeddings/ path can
        // legitimately contain an embedded OOXML package and must not be
        // misclassified as a corrupt OLE file.
        if (normalizedType.contains("oleobject") ||
                normalizedType.equals("application/vnd.ms-office.oleObject")) {
            return true;
        }

        byte[] data = part.getData();
        return hasOleSignature(data);
    }


    private boolean hasOleSignature(byte[] data) {
        if (data == null || data.length < 8) return false;
        return (data[0] & 0xFF) == 0xD0 &&
                (data[1] & 0xFF) == 0xCF &&
                (data[2] & 0xFF) == 0x11 &&
                (data[3] & 0xFF) == 0xE0 &&
                (data[4] & 0xFF) == 0xA1 &&
                (data[5] & 0xFF) == 0xB1 &&
                (data[6] & 0xFF) == 0x1A &&
                (data[7] & 0xFF) == 0xE1;
    }


    // =========================================================
    // FINDING HELPER
    // =========================================================

    private SecurityFinding createFinding(
            OOXMLPart part,
            FindingClassification classification,
            ThreatSeverity severity,
            ThreatType type,
            String evidence,
            String action) {

        return new SecurityFinding(
                classification,
                type,
                severity,
                part,
                null,
                null,
                evidence,
                evidence,
                action
        );
    }
}