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
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
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

    /** Defensive limits for opaque Compound File inspection. */
    private static final int MAX_STORAGE_DEPTH = 32;
    private static final int MAX_ENTRIES = 4096;
    private static final long MAX_STREAM_BYTES = 64L * 1024L * 1024L;

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

                InspectionBudget budget = new InspectionBudget();
                int[] counts =
                        inspectDirectory(
                                root,
                                findings,
                                part,
                                "",
                                0,
                                budget
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
            String parentPath,
            int depth,
            InspectionBudget budget) {

        if (depth > MAX_STORAGE_DEPTH) {
            findings.add(createFinding(
                    part,
                    FindingClassification.SUSPICIOUS,
                    ThreatSeverity.CRITICAL,
                    ThreatType.SUSPICIOUS_ARCHIVE,
                    "OLE storage nesting exceeded the inspection depth limit of " + MAX_STORAGE_DEPTH + ".",
                    "Remove the containing OLE object during CDR."
            ));
            return new int[] {0, 0};
        }

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

            budget.entries++;
            if (budget.entries > MAX_ENTRIES) {
                findings.add(createFinding(
                        part,
                        FindingClassification.SUSPICIOUS,
                        ThreatSeverity.CRITICAL,
                        ThreatType.SUSPICIOUS_ARCHIVE,
                        "OLE entry count exceeded the inspection limit of " + MAX_ENTRIES + ".",
                        "Remove the containing OLE object during CDR."
                ));
                return new int[] {storageCount, streamCount};
            }

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
                                currentPath,
                                depth + 1,
                                budget
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
                    size = ((DocumentEntry) entry).getSize();
                }

                ThreatType streamType = determineStreamType(name);
                boolean macroStream = streamType == ThreatType.VBA_PROJECT ||
                        currentPath.toLowerCase(Locale.ROOT).contains("_vba_project");

                if (macroStream) {
                    findings.add(new SecurityFinding(
                            FindingClassification.THREAT,
                            streamType,
                            ThreatSeverity.CRITICAL,
                            part, null, null,
                            "OLE stream: " + currentPath + ", size: " + size + " bytes",
                            "The embedded OLE Compound File contains VBA project storage/stream content.",
                            "Remove the containing OLE object during CDR."
                    ));
                } else {
                    inspectStreamPayload((DirectoryNode) directory, entry, part, currentPath, findings, size);
                }
            }
        }

        return new int[] {
                storageCount,
                streamCount
        };
    }


    // =========================================================
    // STREAM PAYLOAD INSPECTION
    // =========================================================

    private void inspectStreamPayload(
            DirectoryNode directory,
            Entry entry,
            OOXMLPart part,
            String currentPath,
            List<SecurityFinding> findings,
            long declaredSize) {

        if (!(entry instanceof DocumentEntry)) {
            return;
        }

        if (declaredSize > MAX_STREAM_BYTES) {
            findings.add(createFinding(
                    part,
                    FindingClassification.SUSPICIOUS,
                    ThreatSeverity.CRITICAL,
                    ThreatType.SUSPICIOUS_ARCHIVE,
                    "OLE stream " + currentPath + " is " + declaredSize +
                            " bytes and exceeds the inspection limit of " + MAX_STREAM_BYTES + " bytes.",
                    "Remove the containing OLE object during CDR."
            ));
            return;
        }

        try (DocumentInputStream in = directory.createDocumentInputStream(entry)) {
            byte[] data = readBounded(in, MAX_STREAM_BYTES);
            String normalizedName = stripControlPrefix(entry.getName());

            if ("Ole10Native".equalsIgnoreCase(normalizedName)) {
                inspectOle10Native(data, part, currentPath, findings);
                return;
            }

            Signature signature = detectNativeSignature(data, false);
            if (signature != null) {
                findings.add(new SecurityFinding(
                        FindingClassification.THREAT,
                        signature.type,
                        signature.severity,
                        part, null, null,
                        "OLE stream: " + currentPath + ", size: " + data.length +
                                " bytes; " + signature.evidence,
                        "The OLE stream contains a high-confidence native executable or malware-test signature.",
                        "Remove the containing OLE object during CDR."
                ));
            }
        } catch (Exception e) {
            findings.add(createFinding(
                    part,
                    FindingClassification.SUSPICIOUS,
                    ThreatSeverity.HIGH,
                    ThreatType.OLE_OBJECT,
                    "OLE stream " + currentPath + " could not be safely inspected: " + safeMessage(e),
                    "Remove the containing OLE object during CDR."
            ));
        }
    }

    private void inspectOle10Native(
            byte[] data,
            OOXMLPart part,
            String currentPath,
            List<SecurityFinding> findings) {

        try {
            NativePayload payload = parseOle10Native(data);
            if (payload == null || payload.payload.length == 0) {
                throw new IllegalArgumentException("invalid or empty Ole10Native payload");
            }

            Signature signature = detectNativeSignature(payload.payload, true);
            if (signature != null) {
                findings.add(new SecurityFinding(
                        FindingClassification.THREAT,
                        ThreatType.EXECUTABLE_PAYLOAD,
                        signature.severity,
                        part, null, null,
                        "Ole10Native payload in " + currentPath +
                                ", filename=" + payload.filename +
                                ", command=" + payload.command +
                                ", size=" + payload.payload.length + " bytes; " + signature.evidence,
                        "An OLE Ole10Native record carries active native/script content.",
                        "Remove the containing OLE object during CDR."
                ));
            } else {
                findings.add(new SecurityFinding(
                        FindingClassification.OBSERVATION,
                        ThreatType.OLE_OBJECT,
                        ThreatSeverity.INFO,
                        part, null, null,
                        "Parsed Ole10Native payload in " + currentPath +
                                ", filename=" + payload.filename +
                                ", command=" + payload.command +
                                ", size=" + payload.payload.length + " bytes",
                        "An Ole10Native embedded file was structurally parsed; no high-confidence native signature was found.",
                        "Preserve only after the containing document's full security policy and reconstruction checks succeed."
                ));
            }
        } catch (Exception e) {
            findings.add(createFinding(
                    part,
                    FindingClassification.SUSPICIOUS,
                    ThreatSeverity.HIGH,
                    ThreatType.EMBEDDED_ACTIVE_CONTENT,
                    "Ole10Native stream " + currentPath +
                            " exists but could not be safely parsed: " + safeMessage(e),
                    "Remove the containing OLE object during CDR."
            ));
        }
    }

    private NativePayload parseOle10Native(byte[] data) {
        if (data == null || data.length < 8) throw new IllegalArgumentException("truncated stream");
        Cursor c = new Cursor(data);
        long totalSize = c.readUInt32();
        long recordEnd = 4L + totalSize;
        if (recordEnd > data.length || recordEnd < 8) throw new IllegalArgumentException("invalid record size");
        c.readUInt16();
        String label = c.readAnsiString();
        String filename = c.readAnsiString();
        c.readUInt16();
        c.readUInt16();
        long commandLength = c.readUInt32();
        if (commandLength <= 0 || commandLength > Integer.MAX_VALUE || commandLength > c.remaining())
            throw new IllegalArgumentException("invalid command length");
        String command = decodeNullTerminatedAnsi(c.readBytes((int) commandLength));
        long payloadSize = c.readUInt32();
        if (payloadSize <= 0 || payloadSize > Integer.MAX_VALUE || c.position() + payloadSize > recordEnd || c.position() + payloadSize > data.length)
            throw new IllegalArgumentException("invalid payload size");
        byte[] payload = c.readBytes((int) payloadSize);
        return new NativePayload(label, filename, command, payload);
    }

    private byte[] readBounded(DocumentInputStream in, long max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > max) throw new IOException("stream exceeds inspection limit");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private Signature detectNativeSignature(byte[] data, boolean inspectTextScripts) {
        if (data == null || data.length == 0) return null;
        if (isValidPE(data)) return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL, "valid PE executable signature");
        if (isElf(data)) return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL, "ELF executable signature");
        if (isMachO(data)) return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL, "Mach-O executable signature");
        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        if (text.contains("eicar-standard-antivirus-test-file"))
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.CRITICAL, "EICAR test signature");
        if (inspectTextScripts && (text.startsWith("#!") || text.contains("powershell") ||
                text.contains("wscript.shell") || text.contains("invoke-expression")))
            return new Signature(ThreatType.EXECUTABLE_PAYLOAD, ThreatSeverity.HIGH, "script interpreter/content signature");
        return null;
    }

    private boolean isValidPE(byte[] data) {
        if (data.length < 64 || data[0] != 'M' || data[1] != 'Z') return false;
        int peOffset = (data[0x3c] & 0xff) | ((data[0x3d] & 0xff) << 8) |
                ((data[0x3e] & 0xff) << 16) | ((data[0x3f] & 0xff) << 24);
        return peOffset >= 0 && peOffset <= data.length - 4 &&
                data[peOffset] == 'P' && data[peOffset + 1] == 'E' &&
                data[peOffset + 2] == 0 && data[peOffset + 3] == 0;
    }

    private boolean isElf(byte[] data) {
        return data.length >= 4 && (data[0] & 0xff) == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
    }

    private boolean isMachO(byte[] data) {
        if (data.length < 4) return false;
        int m = ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        int little = (data[0] & 0xff) | ((data[1] & 0xff) << 8) | ((data[2] & 0xff) << 16) | ((data[3] & 0xff) << 24);
        // Do not treat 0xCAFEBABE as Mach-O: that is also the Java class-file magic.
        return m == 0xfeedface || m == 0xfeedfacf || little == 0xcefaedfe || little == 0xcffaedfe;
    }

    private String stripControlPrefix(String name) {
        if (name == null) return "";
        return name.replaceFirst("^\\p{Cntrl}+", "");
    }

    private String decodeNullTerminatedAnsi(byte[] data) {
        int length = 0;
        while (length < data.length && data[length] != 0) length++;
        return new String(data, 0, length, StandardCharsets.ISO_8859_1);
    }

    private String safeMessage(Exception e) {
        String message = e == null ? null : e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : message;
    }

    private static final class InspectionBudget {
        int entries;
    }

    private static final class Signature {
        final ThreatType type;
        final ThreatSeverity severity;
        final String evidence;
        Signature(ThreatType type, ThreatSeverity severity, String evidence) {
            this.type = type;
            this.severity = severity;
            this.evidence = evidence;
        }
    }

    private static final class NativePayload {
        final String label;
        final String filename;
        final String command;
        final byte[] payload;
        NativePayload(String label, String filename, String command, byte[] payload) {
            this.label = label;
            this.filename = filename;
            this.command = command;
            this.payload = payload;
        }
    }

    private static final class Cursor {
        final byte[] data;
        int position;
        Cursor(byte[] data) { this.data = data; }
        int position() { return position; }
        int remaining() { return data.length - position; }
        int readUInt16() { require(2); int v = (data[position] & 0xff) | ((data[position + 1] & 0xff) << 8); position += 2; return v; }
        long readUInt32() { require(4); long v = ((long)data[position] & 0xff) | (((long)data[position+1] & 0xff) << 8) | (((long)data[position+2] & 0xff) << 16) | (((long)data[position+3] & 0xff) << 24); position += 4; return v; }
        String readAnsiString() { int start = position; while (position < data.length && data[position] != 0) position++; if (position >= data.length) throw new IllegalArgumentException("unterminated ANSI string"); String v = new String(data, start, position-start, StandardCharsets.ISO_8859_1); position++; return v; }
        byte[] readBytes(int length) { require(length); byte[] r = new byte[length]; System.arraycopy(data, position, r, 0, length); position += length; return r; }
        void require(int count) { if (count < 0 || count > remaining()) throw new IllegalArgumentException("truncated Ole10Native stream"); }
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