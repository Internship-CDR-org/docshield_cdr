package parsing.ppt;

import parsing.common.DocumentParser;

import model.common.StructureComponent;

import org.apache.poi.hslf.usermodel.HSLFSlide;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PPTStructureParser {

    public List<StructureComponent> parse(
            Path file) throws IOException {

        List<StructureComponent> structures =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSLFSlideShow slideshow =
                     new HSLFSlideShow(inputStream)) {

            int slideNumber = 1;

            for (HSLFSlide slide :
                    slideshow.getSlides()) {

                StructureComponent component =
                        new StructureComponent();

                component.setId(
                        "ppt_slide_" +
                        slideNumber
                );

                component.setType(
                        "SLIDE"
                );

                component.setName(
                        "Slide " +
                        slideNumber
                );

                component.setIndex(
                        slideNumber
                );

                structures.add(component);

                slideNumber++;
            }
        }

        return structures;
    }
}