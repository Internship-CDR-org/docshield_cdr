package parsing.ppt;

import parsing.common.DocumentParser;

import model.common.EmbeddedObjectComponent;
import model.common.ImageComponent;

import org.apache.poi.hslf.usermodel.HSLFObjectShape;
import org.apache.poi.hslf.usermodel.HSLFPictureShape;
import org.apache.poi.hslf.usermodel.HSLFShape;
import org.apache.poi.hslf.usermodel.HSLFSlide;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;
import org.apache.poi.hslf.usermodel.HSLFObjectData;
import org.apache.poi.sl.usermodel.PictureData;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PPTResourceParser {

    // =========================================================
    // IMAGES
    // =========================================================

    public List<ImageComponent> parseImageComponents(
            Path file) throws IOException {

        List<ImageComponent> images =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSLFSlideShow slideshow =
                     new HSLFSlideShow(inputStream)) {

            int slideNumber = 1;
            int imageNumber = 1;

            for (HSLFSlide slide :
                    slideshow.getSlides()) {

                for (HSLFShape shape :
                        slide.getShapes()) {

                    if (shape instanceof HSLFPictureShape) {

                        HSLFPictureShape picture =
                                (HSLFPictureShape) shape;

                        PictureData pictureData =
                                picture.getPictureData();

                        if (pictureData != null) {

                            ImageComponent image =
                                    new ImageComponent();

                            image.setId(
                                    "ppt_image_" +
                                    imageNumber
                            );

                            image.setFileName(
                                    "slide_" +
                                    slideNumber +
                                    "_image_" +
                                    imageNumber
                            );

                            image.setMimeType(
                                    pictureData
                                            .getType()
                                            .contentType
                            );

                            image.setData(
                                    pictureData.getData()
                            );

                            image.setX(
                                    picture
                                            .getAnchor()
                                            .getX()
                            );

                            image.setY(
                                    picture
                                            .getAnchor()
                                            .getY()
                            );

                            images.add(image);

                            imageNumber++;
                        }
                    }
                }

                slideNumber++;
            }
        }

        return images;
    }


    // =========================================================
    // EMBEDDED / OLE OBJECTS
    // =========================================================

    public List<EmbeddedObjectComponent>
        parseEmbeddedObjectComponents(
                Path file) throws IOException {

        List<EmbeddedObjectComponent> objects =
                new ArrayList<>();

        try (InputStream inputStream =
                        Files.newInputStream(file);
                HSLFSlideShow slideshow =
                        new HSLFSlideShow(inputStream)) {

                int slideNumber = 1;
                int objectNumber = 1;

                for (HSLFSlide slide :
                        slideshow.getSlides()) {

                for (HSLFShape shape :
                        slide.getShapes()) {

                        if (!(shape instanceof HSLFObjectShape)) {
                        continue;
                        }

                        HSLFObjectShape objectShape =
                                (HSLFObjectShape) shape;

                        HSLFObjectData objectData =
                                objectShape.getObjectData();

                        if (objectData == null) {
                        continue;
                        }

                        EmbeddedObjectComponent object =
                                new EmbeddedObjectComponent();

                        object.setId(
                                "ppt_object_" +
                                objectNumber
                        );

                        String fileName =
                                objectData.getFileName();

                        if (fileName == null ||
                                fileName.isBlank()) {

                        fileName =
                                "slide_" +
                                slideNumber +
                                "_object_" +
                                objectNumber;
                        }

                        object.setName(fileName);

                        object.setType(
                                objectData.getOLE2ClassName()
                        );

                        try (InputStream dataStream =
                                objectData.getInputStream()) {

                        object.setData(
                                dataStream.readAllBytes()
                        );
                        }

                        object.setActive(true);

                        objects.add(object);

                        objectNumber++;
                }

                slideNumber++;
                }
        }

        return objects;
        }
}