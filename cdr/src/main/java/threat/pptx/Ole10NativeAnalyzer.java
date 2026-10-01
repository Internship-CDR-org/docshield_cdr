package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.Entry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


/**
 * Reads metadata from an OLE Ole10Native stream.
 *
 * This class only reads bytes.
 * It never executes the embedded native payload.
 */
public class Ole10NativeAnalyzer {


    public static class NativePayload {

        private String label;
        private String filename;
        private String sourcePath;
        private String temporaryPath;
        private byte[] payload;


        public String getLabel() {
            return label;
        }

        public String getFilename() {
            return filename;
        }

        public String getSourcePath() {
            return sourcePath;
        }

        public String getTemporaryPath() {
            return temporaryPath;
        }

        public byte[] getPayload() {
            return payload;
        }


        private void setLabel(String value) {
            label = value;
        }

        private void setFilename(String value) {
            filename = value;
        }

        private void setSourcePath(String value) {
            sourcePath = value;
        }

        private void setTemporaryPath(String value) {
            temporaryPath = value;
        }

        private void setPayload(byte[] value) {
            payload = value;
        }
    }


    /**
     * Inspects the current OLE directory for Ole10Native.
     */
    public List<NativePayload> inspect(
            DirectoryNode root) {

        List<NativePayload> results =
                new ArrayList<>();


        if (root == null) {
            return results;
        }


        /*
        * OLE directory names in this sample contain
        * a leading control character:
        *
        *     \x01Ole10Native
        *
        * Therefore we enumerate the directory and
        * normalize the name before matching it.
        */
        DocumentEntry entry = null;

        for (Entry candidate : root) {

            if (candidate == null) {
                continue;
            }

            String name =
                    candidate.getName();

            if (name == null) {
                continue;
            }

            String normalized =
                    name.replaceFirst(
                            "^\\p{Cntrl}+",
                            ""
                    );

            if ("Ole10Native".equalsIgnoreCase(
                    normalized)
                    &&
                    candidate instanceof DocumentEntry) {

                entry =
                        (DocumentEntry) candidate;

                break;
            }
        }


        if (entry == null) {
            return results;
        }


        try {

            byte[] data =
                    readStream(entry);


            NativePayload result =
                    parse(data);


            if (result != null) {
                results.add(result);
            }


        } catch (Exception e) {

            /*
            * For now, parsing failure simply means
            * no parsed result.
            *
            * A later policy layer can classify malformed
            * Ole10Native data separately.
            */
        }


        return results;
    }


    // =========================================================
    // READ STREAM
    // =========================================================

    private byte[] readStream(
            DocumentEntry entry)
            throws IOException {

        try (
                DocumentInputStream input =
                        new DocumentInputStream(entry)
        ) {

            ByteArrayOutputStream output =
                    new ByteArrayOutputStream();


            byte[] buffer =
                    new byte[4096];


            int count;


            while ((count =
                    input.read(buffer)) != -1) {

                output.write(
                        buffer,
                        0,
                        count
                );
            }


            return output.toByteArray();
        }
    }


    // =========================================================
    // PARSE OLE10NATIVE
    // =========================================================

    private NativePayload parse(byte[] data) {

        if (data == null || data.length < 8) {
            return null;
        }

        try {

            Cursor cursor =
                    new Cursor(data);


            // -------------------------------------------------
            // DWORD: total record size
            // -------------------------------------------------

            long totalSize =
                    cursor.readUInt32();


            /*
            * The totalSize field does NOT include its own
            * four bytes.
            */
            long recordEnd =
                    4L + totalSize;


            if (recordEnd > data.length) {
                return null;
            }


            // -------------------------------------------------
            // WORD: flags1
            // -------------------------------------------------

            cursor.readUInt16();


            // -------------------------------------------------
            // ANSI label
            // -------------------------------------------------

            String label =
                    cursor.readAnsiString();


            // -------------------------------------------------
            // ANSI filename
            // -------------------------------------------------

            String filename =
                    cursor.readAnsiString();


            // -------------------------------------------------
            // WORD: flags2
            // -------------------------------------------------

            cursor.readUInt16();


            // -------------------------------------------------
            // WORD: unknown1
            // -------------------------------------------------

            cursor.readUInt16();


            // -------------------------------------------------
            // DWORD: command length
            // -------------------------------------------------

            long commandLengthLong =
                    cursor.readUInt32();


            if (commandLengthLong >
                    Integer.MAX_VALUE) {

                return null;
            }


            int commandLength =
                    (int) commandLengthLong;


            /*
            * The command length includes the terminating
            * null byte.
            */
            if (commandLength <= 0 ||
                    commandLength > cursor.remaining()) {

                return null;
            }


            byte[] commandBytes =
                    cursor.readBytes(commandLength);


            String command =
                    decodeNullTerminatedAnsi(
                            commandBytes
                    );


            // -------------------------------------------------
            // DWORD: actual native payload size
            // -------------------------------------------------

            long payloadSizeLong =
                    cursor.readUInt32();


            if (payloadSizeLong >
                    Integer.MAX_VALUE) {

                return null;
            }


            int payloadSize =
                    (int) payloadSizeLong;


            /*
            * Make sure the payload stays inside BOTH:
            *
            * 1. the Ole10Native record
            * 2. the actual stream
            */
            long payloadEnd =
                    cursor.position() +
                    payloadSize;


            if (payloadEnd > recordEnd ||
                    payloadEnd > data.length) {

                return null;
            }


            // -------------------------------------------------
            // ACTUAL EMBEDDED FILE
            // -------------------------------------------------

            byte[] payload =
                    cursor.readBytes(
                            payloadSize
                    );


            NativePayload result =
                    new NativePayload();


            result.setLabel(label);

            result.setFilename(filename);

            /*
            * For Ole10Native, the command field is the
            * closest equivalent to the extraction/
            * temporary path information we previously
            * called "temporaryPath".
            */
            result.setSourcePath(command);

            result.setTemporaryPath(command);

            /*
            * THIS is now the actual embedded file.
            */
            result.setPayload(payload);


            return result;


        } catch (Exception e) {

            return null;
        }
    }

    private String decodeNullTerminatedAnsi(
            byte[] data) {

        int length = 0;

        while (length < data.length &&
                data[length] != 0) {

            length++;
        }

        return new String(
                data,
                0,
                length,
                StandardCharsets.ISO_8859_1
        );
    }

        private static class Cursor {

        private final byte[] data;

        private int position;


        Cursor(byte[] data) {

            this.data = data;
            this.position = 0;
        }

        int position() {
            return position;
        }


        int remaining() {

            return data.length - position;
        }


        int readUInt16() {

            require(2);

            int value =
                    (data[position] & 0xff)
                    |
                    ((data[position + 1] & 0xff) << 8);

            position += 2;

            return value;
        }


        long readUInt32() {

            require(4);

            long value =
                    ((long) data[position] & 0xff)
                    |
                    (((long) data[position + 1] & 0xff) << 8)
                    |
                    (((long) data[position + 2] & 0xff) << 16)
                    |
                    (((long) data[position + 3] & 0xff) << 24);

            position += 4;

            return value;
        }


        String readAnsiString() {

            int start = position;


            while (position < data.length &&
                    data[position] != 0) {

                position++;
            }


            if (position >= data.length) {
                throw new IllegalArgumentException(
                        "Unterminated ANSI string"
                );
            }


            String value =
                    new String(
                            data,
                            start,
                            position - start,
                            StandardCharsets.ISO_8859_1
                    );


            position++;

            return value;
        }


        byte[] readBytes(int length) {

            if (length < 0 ||
                    length > remaining()) {

                throw new IllegalArgumentException(
                        "Invalid payload length"
                );
            }


            byte[] result =
                    new byte[length];


            System.arraycopy(
                    data,
                    position,
                    result,
                    0,
                    length
            );


            position += length;

            return result;
        }


        private void require(int count) {

            if (count < 0 ||
                    count > remaining()) {

                throw new IllegalArgumentException(
                        "Truncated Ole10Native stream"
                );
            }
        }
    }

    // =========================================================
    // STRING EXTRACTION
    // =========================================================

    private String[] extractStrings(
            byte[] data,
            int start) {

        List<String> strings =
                new ArrayList<>();


        int position = start;


        while (position < data.length &&
                strings.size() < 8) {

            int end = position;


            while (end < data.length &&
                    data[end] != 0) {

                end++;
            }


            if (end == position) {

                position++;
                continue;
            }


            String value =
                    new String(
                            data,
                            position,
                            end - position,
                            StandardCharsets.ISO_8859_1
                    );


            /*
             * Only accept strings that look reasonably
             * like textual metadata.
             */
            if (looksLikeText(value)) {

                strings.add(value);
            }


            if (end >= data.length) {
                break;
            }


            position = end + 1;
        }


        return strings.toArray(
                new String[0]
        );
    }


    private boolean looksLikeText(
            String value) {

        if (value == null ||
                value.isEmpty()) {

            return false;
        }


        int printable = 0;


        for (int i = 0;
             i < value.length();
             i++) {

            char c = value.charAt(i);


            if ((c >= 32 && c <= 126) ||
                    c == '\t') {

                printable++;
            }
        }


        return printable * 100 /
                value.length() >= 80;
    }


    // =========================================================
    // INTEGER
    // =========================================================

    private long readUInt32(
            byte[] data,
            int offset) {

        return ((long) data[offset] & 0xff)
                |
                (((long) data[offset + 1] & 0xff) << 8)
                |
                (((long) data[offset + 2] & 0xff) << 16)
                |
                (((long) data[offset + 3] & 0xff) << 24);
    }
}