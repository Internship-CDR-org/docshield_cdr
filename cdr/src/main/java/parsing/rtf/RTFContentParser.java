package parsing.rtf;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class RTFContentParser {

    public List<String> parseText(Path file)
            throws IOException {

        String rtf = Files.readString(
                file,
                StandardCharsets.ISO_8859_1
        );

        List<String> text = new ArrayList<>();

        StringBuilder current = new StringBuilder();

        int depth = 0;

        boolean escaped = false;
        boolean controlWord = false;
        boolean controlSymbol = false;

        /*
         * Destination groups whose contents
         * are not normal visible document text.
         */
        int ignoredDestinationDepth = -1;

        for (int i = 0; i < rtf.length(); i++) {

            char c = rtf.charAt(i);

            /*
             * Start of a group.
             */
            if (!escaped && c == '{') {

                depth++;

                /*
                 * Check whether this group begins
                 * with a destination we don't want
                 * in normal CONTENT.
                 */
                int next = i + 1;

                if (next < rtf.length()
                        && rtf.charAt(next) == '\\') {

                    int wordStart = next + 1;

                    int wordEnd = wordStart;

                    while (wordEnd < rtf.length()
                            && Character.isLetter(
                            rtf.charAt(wordEnd))) {

                        wordEnd++;
                    }

                    String word =
                            rtf.substring(
                                    wordStart,
                                    wordEnd
                            );

                    if (isIgnoredDestination(word)) {

                        ignoredDestinationDepth =
                                depth;
                    }
                }

                continue;
            }

            /*
             * End of a group.
             */
            if (!escaped && c == '}') {

                if (ignoredDestinationDepth == depth) {
                    ignoredDestinationDepth = -1;
                }

                depth--;

                continue;
            }

            /*
             * Skip everything inside special
             * destination groups.
             */
            if (ignoredDestinationDepth != -1) {
                continue;
            }

            /*
             * Escape/control sequence.
             */
            if (escaped) {

                escaped = false;

                /*
                 * Hex encoded character:
                 *
                 * \'e9
                 */
                if (c == '\''
                        && i + 2 < rtf.length()) {

                    String hex =
                            rtf.substring(
                                    i + 1,
                                    i + 3
                            );

                    try {

                        int value =
                                Integer.parseInt(
                                        hex,
                                        16
                                );

                        current.append(
                                (char) value
                        );

                        i += 2;

                    } catch (NumberFormatException ignored) {
                    }

                    continue;
                }

                /*
                 * Escaped literal characters.
                 */
                if (c == '\\'
                        || c == '{'
                        || c == '}') {

                    current.append(c);
                    continue;
                }

                /*
                 * Control symbol such as:
                 *
                 * \~
                 * \-
                 * \_
                 */
                if (!Character.isLetter(c)) {

                    if (c == '~') {
                        current.append(' ');
                    }

                    continue;
                }

                /*
                 * Control word.
                 */
                int wordStart = i;

                int wordEnd = i;

                while (wordEnd < rtf.length()
                        && Character.isLetter(
                        rtf.charAt(wordEnd))) {

                    wordEnd++;
                }

                String word =
                        rtf.substring(
                                wordStart,
                                wordEnd
                        );

                /*
                 * Handle paragraph / line breaks.
                 */
                if ("par".equals(word)
                        || "line".equals(word)) {

                    current.append('\n');
                }

                /*
                 * Skip optional numeric parameter.
                 */
                i = wordEnd - 1;

                if (i + 1 < rtf.length()
                        && rtf.charAt(i + 1) == '-') {

                    i++;

                    while (i + 1 < rtf.length()
                            && Character.isDigit(
                            rtf.charAt(i + 1))) {

                        i++;
                    }

                } else {

                    while (i + 1 < rtf.length()
                            && Character.isDigit(
                            rtf.charAt(i + 1))) {

                        i++;
                    }
                }

                /*
                 * RTF control words are not
                 * visible document text.
                 */

                continue;
            }

            /*
             * Backslash begins a control sequence.
             */
            if (c == '\\') {

                escaped = true;
                continue;
            }

            /*
             * Ignore RTF line wrapping.
             */
            if (c == '\r'
                    || c == '\n') {

                continue;
            }

            /*
             * Normal visible character.
             */
            current.append(c);
        }

        String result =
                current.toString()
                        .replaceAll(
                                "[ \\t]+",
                                " "
                        )
                        .replaceAll(
                                "\\n{3,}",
                                "\n\n"
                        )
                        .trim();

        if (!result.isEmpty()) {
            text.add(result);
        }

        return text;
    }

    private boolean isIgnoredDestination(
            String word) {

        return word.equals("fonttbl")
                || word.equals("colortbl")
                || word.equals("stylesheet")
                || word.equals("info")
                || word.equals("generator")
                || word.equals("listtable")
                || word.equals("listoverridetable")
                || word.equals("revtbl")
                || word.equals("xmlnstbl")
                || word.equals("pict")
                || word.equals("object")
                || word.equals("header")
                || word.equals("footer")
                || word.equals("headerl")
                || word.equals("headerr")
                || word.equals("footerl")
                || word.equals("footerr");
    }
}