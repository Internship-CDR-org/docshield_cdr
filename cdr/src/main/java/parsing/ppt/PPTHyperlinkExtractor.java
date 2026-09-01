package parsing.ppt;

import parsing.common.HyperlinkExtractor;


import model.common.HyperlinkComponent;

import org.apache.poi.hslf.usermodel.HSLFHyperlink;
import org.apache.poi.hslf.usermodel.HSLFSlide;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;
import org.apache.poi.hslf.usermodel.HSLFTextShape;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PPTHyperlinkExtractor
        implements HyperlinkExtractor {

    @Override
    public List<HyperlinkComponent> extract(
            Path file) throws IOException {

        List<HyperlinkComponent> hyperlinks =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSLFSlideShow slideshow =
                     new HSLFSlideShow(inputStream)) {

            int hyperlinkNumber = 1;

            for (HSLFSlide slide :
                    slideshow.getSlides()) {

                for (var shape :
                        slide.getShapes()) {

                    if (!(shape instanceof HSLFTextShape)) {
                        continue;
                    }

                    HSLFTextShape textShape =
                            (HSLFTextShape) shape;

                    List<HSLFHyperlink> links =
                            textShape.getHyperlinks();

                    if (links == null) {
                        continue;
                    }

                    for (HSLFHyperlink link : links) {

                        HyperlinkComponent component =
                                new HyperlinkComponent();

                        component.setId(
                                "ppt_hyperlink_" +
                                hyperlinkNumber
                        );

                        String displayText =
                                link.getLabel();

                        String target =
                                link.getAddress();

                        component.setDisplayText(
                                displayText
                        );

                        component.setTarget(
                                target
                        );

                        hyperlinks.add(component);

                        hyperlinkNumber++;
                    }
                }
            }
        }

        return hyperlinks;
    }
}