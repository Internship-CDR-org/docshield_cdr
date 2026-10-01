package parsing.rtf;

import parsing.common.HyperlinkExtractor;


import model.common.HyperlinkComponent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RTFHyperlinkExtractor
        implements HyperlinkExtractor {

    private static final Pattern HYPERLINK_PATTERN =
            Pattern.compile(
                    "\\\\fldinst\\s+HYPERLINK\\s+\"([^\"]+)\"",
                    Pattern.CASE_INSENSITIVE
            );

    private static final Pattern DISPLAY_PATTERN =
            Pattern.compile(
                    "\\\\fldrslt\\s+([^{}]+)",
                    Pattern.CASE_INSENSITIVE
            );


    @Override
    public List<HyperlinkComponent> extract(
            Path file) throws IOException {

        List<HyperlinkComponent> hyperlinks =
                new ArrayList<>();

        String rtf =
                Files.readString(
                        file,
                        StandardCharsets.ISO_8859_1
                );

        Matcher targetMatcher =
                HYPERLINK_PATTERN.matcher(rtf);

        int number = 1;

        while (targetMatcher.find()) {

            String target =
                    targetMatcher.group(1);

            String displayText =
                    extractDisplayText(
                            rtf,
                            targetMatcher.end()
                    );

            HyperlinkComponent component =
                    new HyperlinkComponent();

            component.setId(
                    "rtf_hyperlink_" +
                    number
            );

            component.setTarget(
                    target
            );

            component.setDisplayText(
                    displayText
            );

            hyperlinks.add(component);

            number++;
        }

        return hyperlinks;
    }


    private String extractDisplayText(
            String rtf,
            int start) {

        Matcher matcher =
                DISPLAY_PATTERN.matcher(
                        rtf
                );

        matcher.region(
                start,
                rtf.length()
        );

        if (matcher.find()) {

            return matcher.group(1)
                    .trim();
        }

        return "";
    }
}