package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.ImageComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.PDResources;

import javax.imageio.ImageIO;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFResourceParser {

    // =========================================================
    // IMAGES
    // =========================================================

    public List<ImageComponent> parseImageComponents(
            Path file) throws IOException {

        List<ImageComponent> images =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageNumber = 1;
            int imageNumber = 1;

            for (PDPage page :
                    document.getPages()) {

                PDResources resources =
                        page.getResources();

                if (resources == null) {
                    pageNumber++;
                    continue;
                }

                for (COSName name :
                        resources.getXObjectNames()) {

                    PDXObject xObject =
                            resources.getXObject(name);

                    if (xObject instanceof PDImageXObject) {

                        PDImageXObject image =
                                (PDImageXObject) xObject;

                        ImageComponent component =
                                createImageComponent(
                                        image,
                                        "pdf_image_" +
                                                imageNumber,
                                        "page_" +
                                                pageNumber +
                                                "_" +
                                                name.getName()
                                );

                        images.add(component);

                        imageNumber++;
                    }

                    else if (xObject instanceof PDFormXObject) {

                        PDFormXObject form =
                                (PDFormXObject) xObject;

                        imageNumber =
                                parseFormImages(
                                        form,
                                        pageNumber,
                                        images,
                                        imageNumber
                                );
                    }
                }

                pageNumber++;
            }
        }

        return images;
    }


    // =========================================================
    // FORM XOBJECT IMAGES
    // =========================================================

    private int parseFormImages(
            PDFormXObject form,
            int pageNumber,
            List<ImageComponent> images,
            int imageNumber)
            throws IOException {

        PDResources resources =
                form.getResources();

        if (resources == null) {
            return imageNumber;
        }

        for (COSName name :
                resources.getXObjectNames()) {

            PDXObject xObject =
                    resources.getXObject(name);

            if (xObject instanceof PDImageXObject) {

                PDImageXObject image =
                        (PDImageXObject) xObject;

                ImageComponent component =
                        createImageComponent(
                                image,
                                "pdf_image_" +
                                        imageNumber,
                                "page_" +
                                        pageNumber +
                                        "_form_" +
                                        name.getName()
                        );

                images.add(component);

                imageNumber++;
            }

            else if (xObject instanceof PDFormXObject) {

                imageNumber =
                        parseFormImages(
                                (PDFormXObject) xObject,
                                pageNumber,
                                images,
                                imageNumber
                        );
            }
        }

        return imageNumber;
    }


    // =========================================================
    // IMAGE COMPONENT CREATION
    // =========================================================

    private ImageComponent createImageComponent(
            PDImageXObject image,
            String id,
            String fileName)
            throws IOException {

        ImageComponent component =
                new ImageComponent();

        component.setId(id);

        component.setFileName(
                fileName
        );

        component.setMimeType(
                determineMimeType(image)
        );

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        String suffix =
                image.getSuffix();

        String format =
                suffix != null
                        ? suffix.toLowerCase()
                        : "png";

        if (!ImageIO.write(
                image.getImage(),
                format,
                output)) {

        // Fallback to PNG if the original
        // image format isn't supported by ImageIO.
        output.reset();

        ImageIO.write(
                image.getImage(),
                "png",
                output
        );

        format = "png";

        component.setMimeType(
                "image/png"
        );
        }

        component.setData(
                output.toByteArray()
        );

        component.setWidth(
                image.getWidth()
        );

        component.setHeight(
                image.getHeight()
        );

        return component;
    }


    // =========================================================
    // MIME TYPE
    // =========================================================

    private String determineMimeType(
            PDImageXObject image) {

        String suffix =
                image.getSuffix();

        if (suffix == null) {
            return "application/octet-stream";
        }

        switch (suffix.toLowerCase()) {

            case "jpg":
            case "jpeg":
                return "image/jpeg";

            case "png":
                return "image/png";

            case "tif":
            case "tiff":
                return "image/tiff";

            case "jp2":
                return "image/jp2";

            case "bmp":
                return "image/bmp";

            default:
                return "image/" +
                        suffix.toLowerCase();
        }
    }
}