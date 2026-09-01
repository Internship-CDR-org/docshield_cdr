package parsing.ppt;

import parsing.common.DocumentParser;

import org.apache.poi.hslf.usermodel.HSLFSlide;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;
import org.apache.poi.hslf.usermodel.HSLFTextShape;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PPTContentParser {

    public List<String> parseText(Path file)
            throws IOException {

        List<String> content =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSLFSlideShow slideshow =
                     new HSLFSlideShow(inputStream)) {

            int slideNumber = 1;

            for (HSLFSlide slide :
                    slideshow.getSlides()) {

                StringBuilder slideText =
                        new StringBuilder();

                for (var shape :
                        slide.getShapes()) {

                    if (shape instanceof HSLFTextShape) {

                        HSLFTextShape textShape =
                                (HSLFTextShape) shape;

                        String text =
                                textShape.getText();

                        if (text != null
                                && !text.isBlank()) {

                            slideText.append(text)
                                    .append("\n");
                        }
                    }
                }

                String result =
                        slideText.toString().trim();

                if (!result.isEmpty()) {

                    content.add(
                            "Slide "
                                    + slideNumber
                                    + ":\n"
                                    + result
                    );
                }

                slideNumber++;
            }
        }

        return content;
    }
}