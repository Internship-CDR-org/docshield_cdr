package parsing.rtf;

import parsing.common.DocumentParser;

import model.common.EmbeddedObjectComponent;
import model.common.ImageComponent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class RTFResourceParser {

    // =========================================================
    // IMAGES
    // =========================================================

    public List<ImageComponent> parseImageComponents(
            Path file) throws IOException {

        List<ImageComponent> images =
                new ArrayList<>();

        String rtf = Files.readString(
                file,
                StandardCharsets.ISO_8859_1
        );

        int searchFrom = 0;
        int imageNumber = 1;

        while (true) {

            int start =
                    rtf.indexOf(
                            "{\\pict",
                            searchFrom
                    );

            if (start == -1) {
                break;
            }

            int end =
                    findGroupEnd(
                            rtf,
                            start
                    );

            if (end == -1) {
                break;
            }

            String imageGroup =
                    rtf.substring(
                            start,
                            end + 1
                    );

            ImageComponent image =
                    parseImageGroup(
                            imageGroup,
                            imageNumber
                    );

            if (image != null) {

                images.add(image);
                imageNumber++;
            }

            searchFrom = end + 1;
        }

        return images;
    }


    private ImageComponent parseImageGroup(
            String group,
            int imageNumber) {

        String mimeType = null;

        if (group.contains("\\pngblip")) {
            mimeType = "image/png";
        }
        else if (group.contains("\\jpegblip")) {
            mimeType = "image/jpeg";
        }
        else if (group.contains("\\emfblip")) {
            mimeType = "image/emf";
        }
        else if (group.contains("\\wmetafile")) {
            mimeType = "image/wmf";
        }

        if (mimeType == null) {
            return null;
        }

        StringBuilder hex =
                new StringBuilder();

        boolean inControlWord = false;

        for (int i = 0;
             i < group.length();
             i++) {

            char c = group.charAt(i);

            if (c == '\\') {
                inControlWord = true;
                continue;
            }

            if (inControlWord) {

                if (Character.isLetter(c) ||
                        Character.isDigit(c)) {

                    continue;
                }

                inControlWord = false;
            }

            if (isHexCharacter(c)) {
                hex.append(c);
            }
        }

        if (hex.length() < 2) {
            return null;
        }

        byte[] data =
                decodeHex(
                        hex.toString()
                );

        if (data.length == 0) {
            return null;
        }

        ImageComponent image =
                new ImageComponent();

        image.setId(
                "rtf_image_" +
                imageNumber
        );

        image.setFileName(
                "rtf_image_" +
                imageNumber
        );

        image.setMimeType(
                mimeType
        );

        image.setData(data);

        return image;
    }


    // =========================================================
    // EMBEDDED OBJECTS
    // =========================================================

    public List<EmbeddedObjectComponent>
    parseEmbeddedObjectComponents(
            Path file) throws IOException {

        List<EmbeddedObjectComponent> objects =
                new ArrayList<>();

        String rtf = Files.readString(
                file,
                StandardCharsets.ISO_8859_1
        );

        int searchFrom = 0;
        int objectNumber = 1;

        while (true) {

            int start =
                    rtf.indexOf(
                            "{\\object",
                            searchFrom
                    );

            if (start == -1) {
                break;
            }

            int end =
                    findGroupEnd(
                            rtf,
                            start
                    );

            if (end == -1) {
                break;
            }

            String objectGroup =
                    rtf.substring(
                            start,
                            end + 1
                    );

            EmbeddedObjectComponent object =
                    parseObjectGroup(
                            objectGroup,
                            objectNumber
                    );

            if (object != null) {

                objects.add(object);
                objectNumber++;
            }

            searchFrom = end + 1;
        }

        return objects;
    }


    private EmbeddedObjectComponent parseObjectGroup(
            String group,
            int objectNumber) {

        String name =
                extractControlValue(
                        group,
                        "\\objname"
                );

        String type =
                extractControlValue(
                        group,
                        "\\objclass"
                );

        String objData =
                extractObjData(
                        group
                );

        if (objData == null ||
                objData.isEmpty()) {

            return null;
        }

        byte[] data =
                decodeHex(
                        objData
                );

        if (data.length == 0) {
            return null;
        }

        EmbeddedObjectComponent object =
                new EmbeddedObjectComponent();

        object.setId(
                "rtf_object_" +
                objectNumber
        );

        object.setName(
                name != null
                        ? name
                        : "rtf_object_" +
                          objectNumber
        );

        object.setType(
                type != null
                        ? type
                        : "unknown"
        );

        object.setData(data);

        object.setActive(true);

        return object;
    }


    private String extractObjData(
            String group) {

        int marker =
                group.indexOf(
                        "\\objdata"
                );

        if (marker == -1) {
            return null;
        }

        int start =
                marker + "\\objdata".length();

        StringBuilder hex =
                new StringBuilder();

        for (int i = start;
             i < group.length();
             i++) {

            char c =
                    group.charAt(i);

            if (isHexCharacter(c)) {
                hex.append(c);
            }
        }

        return hex.toString();
    }


    private String extractControlValue(
            String group,
            String controlWord) {

        int start =
                group.indexOf(
                        controlWord
                );

        if (start == -1) {
            return null;
        }

        start += controlWord.length();

        while (start < group.length() &&
                Character.isWhitespace(
                        group.charAt(start))) {

            start++;
        }

        StringBuilder value =
                new StringBuilder();

        for (int i = start;
             i < group.length();
             i++) {

            char c =
                    group.charAt(i);

            if (Character.isWhitespace(c) ||
                    c == '\\' ||
                    c == '{' ||
                    c == '}') {

                break;
            }

            value.append(c);
        }

        return value.length() > 0
                ? value.toString()
                : null;
    }


    // =========================================================
    // HEX DECODING
    // =========================================================

    private boolean isHexCharacter(
            char c) {

        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }


    private byte[] decodeHex(
            String hex) {

        int length =
                hex.length() / 2;

        byte[] data =
                new byte[length];

        for (int i = 0;
             i < length;
             i++) {

            int high =
                    Character.digit(
                            hex.charAt(i * 2),
                            16
                    );

            int low =
                    Character.digit(
                            hex.charAt(i * 2 + 1),
                            16
                    );

            if (high < 0 || low < 0) {
                return new byte[0];
            }

            data[i] =
                    (byte) (
                            (high << 4)
                                    | low
                    );
        }

        return data;
    }


    // =========================================================
    // RTF GROUP END
    // =========================================================

    private int findGroupEnd(
            String rtf,
            int start) {

        int depth = 0;
        boolean escaped = false;

        for (int i = start;
             i < rtf.length();
             i++) {

            char c =
                    rtf.charAt(i);

            if (escaped) {

                escaped = false;
                continue;
            }

            if (c == '\\') {

                escaped = true;
                continue;
            }

            if (c == '{') {

                depth++;
            }
            else if (c == '}') {

                depth--;

                if (depth == 0) {
                    return i;
                }
            }
        }

        return -1;
    }
}