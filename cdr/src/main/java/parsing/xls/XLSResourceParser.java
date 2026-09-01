package parsing.xls;

import parsing.common.DocumentParser;

import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;

import org.apache.poi.hssf.usermodel.HSSFObjectData;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.PictureData;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XLSResourceParser {

    public List<ImageComponent> parseImageComponents(
        Path file) throws IOException {

        List<ImageComponent> images =
        new ArrayList<>();
        
        try (InputStream inputStream =
                     Files.newInputStream(file);
                     HSSFWorkbook workbook =
                     new HSSFWorkbook(inputStream)) {

            int imageNumber = 1;

            for (PictureData picture :
                    workbook.getAllPictures()) {

                        ImageComponent image =
                        new ImageComponent();
                        
                image.setId(
                        "xls_image_" +
                        imageNumber
                    );
                    
                    image.setFileName(
                        "xls_image_" +
                        imageNumber
                    );

                    image.setMimeType(
                        picture.getMimeType()
                    );

                image.setData(
                        picture.getData()
                    );
                    
                    images.add(image);
                    
                    imageNumber++;
                }
        }
        
        return images;
    }

    public List<EmbeddedObjectComponent>
        parseEmbeddedObjectComponents(
                Path file) throws IOException {

            List<EmbeddedObjectComponent> objects =
                    new ArrayList<>();

            try (InputStream inputStream =
                        Files.newInputStream(file);
                HSSFWorkbook workbook =
                        new HSSFWorkbook(inputStream)) {

                int objectNumber = 1;

                for (HSSFObjectData objectData :
                        workbook.getAllEmbeddedObjects()) {

                    EmbeddedObjectComponent object =
                            new EmbeddedObjectComponent();

                    object.setId(
                            "xls_object_" +
                            objectNumber
                    );

                    object.setName(
                            "xls_object_" +
                            objectNumber
                    );

                    object.setType(
                            objectData.getOLE2ClassName()
                    );

                    object.setData(
                            objectData.getObjectData()
                    );

                    object.setActive(true);

                    objects.add(object);

                    objectNumber++;
                }
            }

        return objects;
    }

}