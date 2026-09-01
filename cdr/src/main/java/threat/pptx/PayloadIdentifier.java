package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.nio.charset.StandardCharsets;
import java.util.Locale;


/**
 * Identifies an extracted payload without executing it.
 *
 * This class performs identification only.
 * Security classification belongs to a separate policy layer.
 */
public class PayloadIdentifier {


    public static class Identification {

        private final PayloadType type;
        private final String filename;
        private final String extension;
        private final String evidence;


        public Identification(
                PayloadType type,
                String filename,
                String extension,
                String evidence) {

            this.type = type;
            this.filename = filename;
            this.extension = extension;
            this.evidence = evidence;
        }


        public PayloadType getType() {
            return type;
        }


        public String getFilename() {
            return filename;
        }


        public String getExtension() {
            return extension;
        }


        public String getEvidence() {
            return evidence;
        }
    }


    /**
     * Identify a payload using both its filename and
     * its actual byte content.
     */
    public Identification identify(
            String filename,
            byte[] payload) {

        String extension =
                extractExtension(filename);


        PayloadType contentType =
                identifyByContent(payload);


        /*
         * Content evidence has priority over the
         * filename extension.
         */
        if (contentType != PayloadType.UNKNOWN) {

            return new Identification(
                    contentType,
                    filename,
                    extension,
                    "Payload content matches "
                    + contentType
            );
        }


        /*
         * Fall back to extension only when the
         * content itself doesn't provide enough
         * evidence.
         */
        PayloadType extensionType =
                identifyByExtension(extension);


        return new Identification(
                extensionType,
                filename,
                extension,
                "Payload identified using filename extension"
        );
    }


    // =========================================================
    // CONTENT IDENTIFICATION
    // =========================================================

    private PayloadType identifyByContent(
            byte[] payload) {

        if (payload == null ||
                payload.length == 0) {

            return PayloadType.UNKNOWN;
        }


        /*
         * Windows batch files are text based.
         */
        String text =
                new String(
                        payload,
                        StandardCharsets.ISO_8859_1
                );


        String normalized =
                text
                        .trim()
                        .toLowerCase(Locale.ROOT);


        if (normalized.startsWith(
                "@echo off")
                ||
                normalized.startsWith(
                        "echo off")
                ||
                normalized.contains(
                        "\n@echo off")) {

            return PayloadType.WINDOWS_BATCH_SCRIPT;
        }


        /*
         * PowerShell indicators.
         */
        if (normalized.contains(
                "powershell")
                ||
                normalized.contains(
                        "$env:")
                ||
                normalized.contains(
                        "invoke-expression")) {

            return PayloadType.POWERSHELL_SCRIPT;
        }


        /*
         * VBScript indicators.
         */
        if (normalized.startsWith(
                "dim ")
                ||
                normalized.contains(
                        "createobject(\"wscript.shell\")")) {

            return PayloadType.VBS_SCRIPT;
        }


        /*
         * JavaScript indicators.
         */
        if (normalized.contains(
                "function ")
                ||
                normalized.contains(
                        "javascript:")) {

            return PayloadType.JAVASCRIPT;
        }


        /*
         * Windows PE executable.
         *
         * PE files begin with:
         *
         * MZ
         */
        if (payload.length >= 2 &&
                payload[0] == 'M' &&
                payload[1] == 'Z') {

            return PayloadType.PE_EXECUTABLE;
        }


        /*
         * ELF executable.
         */
        if (payload.length >= 4 &&
                (payload[0] & 0xff) == 0x7f &&
                payload[1] == 'E' &&
                payload[2] == 'L' &&
                payload[3] == 'F') {

            return PayloadType.ELF_EXECUTABLE;
        }


        /*
         * PDF.
         */
        if (startsWith(
                payload,
                "%PDF-")) {

            return PayloadType.PDF_DOCUMENT;
        }


        /*
         * ZIP.
         */
        if (payload.length >= 4 &&
                (payload[0] & 0xff) == 0x50 &&
                (payload[1] & 0xff) == 0x4B &&
                (payload[2] & 0xff) == 0x03 &&
                (payload[3] & 0xff) == 0x04) {

            return PayloadType.ZIP_ARCHIVE;
        }


        return PayloadType.UNKNOWN;
    }


    // =========================================================
    // EXTENSION IDENTIFICATION
    // =========================================================

    private PayloadType identifyByExtension(
            String extension) {

        if (extension == null) {
            return PayloadType.UNKNOWN;
        }


        switch (
                extension.toLowerCase(Locale.ROOT)
        ) {

            case ".bat":
                return PayloadType.WINDOWS_BATCH_SCRIPT;

            case ".cmd":
                return PayloadType.WINDOWS_COMMAND_SCRIPT;

            case ".ps1":
                return PayloadType.POWERSHELL_SCRIPT;

            case ".vbs":
                return PayloadType.VBS_SCRIPT;

            case ".js":
                return PayloadType.JAVASCRIPT;

            case ".pdf":
                return PayloadType.PDF_DOCUMENT;

            case ".svg":
                return PayloadType.SVG;

            case ".png":
            case ".jpg":
            case ".jpeg":
            case ".gif":
                return PayloadType.IMAGE;

            default:
                return PayloadType.UNKNOWN;
        }
    }


    // =========================================================
    // EXTENSION
    // =========================================================

    private String extractExtension(
            String filename) {

        if (filename == null) {
            return "";
        }


        int slash =
                Math.max(
                        filename.lastIndexOf('\\'),
                        filename.lastIndexOf('/')
                );


        String name =
                filename.substring(
                        slash + 1
                );


        int dot =
                name.lastIndexOf('.');


        if (dot <= 0 ||
                dot == name.length() - 1) {

            return "";
        }


        return name.substring(dot);
    }


    // =========================================================
    // BYTE PREFIX
    // =========================================================

    private boolean startsWith(
            byte[] data,
            String value) {

        byte[] prefix =
                value.getBytes(
                        StandardCharsets.ISO_8859_1
                );


        if (data.length < prefix.length) {
            return false;
        }


        for (int i = 0;
             i < prefix.length;
             i++) {

            if (data[i] != prefix[i]) {
                return false;
            }
        }


        return true;
    }
}