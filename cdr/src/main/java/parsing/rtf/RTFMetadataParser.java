package parsing.rtf;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RTFMetadataParser {

    private static final String INFO_GROUP =
            "\\{\\\\info.*?\\}";

    private static final String[] FIELDS = {
            "title",
            "subject",
            "author",
            "keywords",
            "comment"
    };

    public Map<String, String> parse(
            Path file) throws IOException {

        Map<String, String> metadata =
                new LinkedHashMap<>();

        String rtf =
                Files.readString(
                        file,
                        StandardCharsets.ISO_8859_1
                );

        Matcher infoMatcher =
                Pattern.compile(
                        INFO_GROUP,
                        Pattern.CASE_INSENSITIVE |
                        Pattern.DOTALL
                ).matcher(rtf);

        if (!infoMatcher.find()) {
            return metadata;
        }

        String info =
                infoMatcher.group();

        for (String field : FIELDS) {

            Pattern pattern =
                    Pattern.compile(
                            "\\\\" +
                            field +
                            "\\s+([^{}\\\\]+)",
                            Pattern.CASE_INSENSITIVE
                    );

            Matcher matcher =
                    pattern.matcher(info);

            if (matcher.find()) {

                String value =
                        matcher.group(1)
                                .trim();

                if (!value.isEmpty()) {

                    metadata.put(
                            field,
                            value
                    );
                }
            }
        }

        return metadata;
    }
}