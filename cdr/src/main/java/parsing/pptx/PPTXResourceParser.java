package parsing.pptx;

import parsing.common.DocumentParser;

import model.common.ImageComponent;

import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFPictureData;
import org.apache.poi.xslf.usermodel.XSLFPictureShape;
import org.apache.poi.xslf.usermodel.XSLFShape;
import org.apache.poi.xslf.usermodel.XSLFSlide;

import java.awt.geom.Rectangle2D;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PPTXResourceParser {

    // =========================================================
    // IMAGE COMPONENTS
    // =========================================================

    public List<ImageComponent> parseImageComponents(
            Path file)
            throws IOException {

        List<ImageComponent> images =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             XMLSlideShow presentation =
                     new XMLSlideShow(inputStream)) {

            int slideNumber = 1;
            int imageNumber = 1;

            for (XSLFSlide slide :
                    presentation.getSlides()) {

                for (XSLFShape shape :
                        slide.getShapes()) {

                    if (!(shape instanceof XSLFPictureShape)) {
                        continue;
                    }

                    XSLFPictureShape picture =
                            (XSLFPictureShape) shape;

                    XSLFPictureData pictureData =
                            picture.getPictureData();

                    if (pictureData == null) {
                        continue;
                    }

                    byte[] data =
                            pictureData.getData();

                    if (data == null ||
                            data.length == 0) {
                        continue;
                    }

                    ImageComponent component =
                            new ImageComponent();

                    component.setId(
                            "pptx_image_" +
                                    imageNumber
                    );

                    // -------------------------------------------------
                    // Slide number
                    // -------------------------------------------------

                    component.setPageNumber(
                            slideNumber
                    );

                    // -------------------------------------------------
                    // Original image information
                    // -------------------------------------------------

                    component.setFileName(
                            pictureData.getFileName()
                    );

                    component.setMimeType(
                            pictureData
                                    .getContentType()
                    );

                    component.setData(
                            data
                    );

                    // -------------------------------------------------
                    // Position and displayed dimensions
                    // -------------------------------------------------

                    Rectangle2D anchor =
                            picture.getAnchor();

                    if (anchor != null) {

                        component.setX(
                                anchor.getX()
                        );

                        component.setY(
                                anchor.getY()
                        );

                        component.setWidth(
                                (int) Math.round(
                                        anchor.getWidth()
                                )
                        );

                        component.setHeight(
                                (int) Math.round(
                                        anchor.getHeight()
                                )
                        );
                    }

                    images.add(
                            component
                    );

                    imageNumber++;
                }

                slideNumber++;
            }
        }

        return images;
    }


    // =========================================================
    // LEGACY IMAGE PARSER
    // =========================================================

    public List<String> parseImages(
            Path file)
            throws IOException {

        List<String> images =
                new ArrayList<>();

        for (ImageComponent component :
                parseImageComponents(file)) {

            images.add(
                    component.getFileName()
            );
        }

        return images;
    }


    // =========================================================
    // EMBEDDED OBJECTS
    // =========================================================

    public List<String> parseEmbeddedObjects(
            Path file)
            throws IOException {

        List<String> objects =
                new ArrayList<>();

        /*
         * Keep the existing embedded-object
         * detection for now.
         *
         * We will convert embedded objects
         * into EmbeddedObjectComponent later
         * when we focus on that part of the
         * reconstruction.
         */

        try (java.util.zip.ZipFile zipFile =
                     new java.util.zip.ZipFile(
                             file.toFile())) {

            var entries =
                    zipFile.entries();

            while (entries.hasMoreElements()) {

                java.util.zip.ZipEntry entry =
                        entries.nextElement();

                if (entry.isDirectory()) {
                    continue;
                }

                String name =
                        entry.getName();

                if (name.startsWith(
                        "ppt/embeddings/")) {

                    objects.add(name);
                }
            }
        }

        return objects;
    }
}