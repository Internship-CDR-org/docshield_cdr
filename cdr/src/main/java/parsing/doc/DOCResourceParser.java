package parsing.doc;

import parsing.common.DocumentParser;

import model.common.ImageComponent;

import org.apache.poi.hwpf.HWPFDocument;
import org.apache.poi.hwpf.usermodel.Picture;
import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.DocumentNode;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DOCResourceParser {

        public List<ImageComponent> parseImageComponents(Path file)
                throws IOException {

        List<ImageComponent> images =
                new ArrayList<>();

        try (InputStream inputStream =
                        Files.newInputStream(file);
                HWPFDocument document =
                        new HWPFDocument(inputStream)) {

                List<Picture> pictures =
                        document.getPicturesTable()
                                .getAllPictures();

                int index = 0;

                for (Picture picture : pictures) {

                String filename =
                        picture.suggestFullFileName();

                byte[] imageData =
                        picture.getContent();

                ImageComponent image =
                        new ImageComponent();

                image.setId(
                        "image_" + index
                );

                image.setFileName(filename);

                image.setMimeType(
                        picture.getMimeType()
                );

                image.setData(imageData);

                image.setWidth(
                        picture.getWidth()
                );

                image.setHeight(
                        picture.getHeight()
                );

                images.add(image);

                index++;
                }
        }

        return images;
        }

    public List<String> parseEmbeddedObjects(Path file)
            throws IOException {

        List<String> objects =
                new ArrayList<>();

        try (POIFSFileSystem filesystem =
                     new POIFSFileSystem(file.toFile())) {

            DirectoryNode root =
                    filesystem.getRoot();

            inspectDirectory(
                    root,
                    "",
                    objects
            );
        }

        return objects;
    }

    private void inspectDirectory(
            DirectoryNode directory,
            String path,
            List<String> objects)
            throws IOException {

        for (org.apache.poi.poifs.filesystem.Entry entry :
                directory) {

            String currentPath =
                    path.isEmpty()
                            ? entry.getName()
                            : path + "/" + entry.getName();

            if (entry instanceof DirectoryNode) {

                inspectDirectory(
                        (DirectoryNode) entry,
                        currentPath,
                        objects
                );

            } else if (entry instanceof DocumentNode) {

                String name =
                        entry.getName();

                /*
                 * Common OLE / embedded-object
                 * related streams.
                 */
                if (name.equalsIgnoreCase("ObjectPool")
                        || name.equalsIgnoreCase("\u0001Ole")
                        || name.equalsIgnoreCase("\u0001CompObj")
                        || name.equalsIgnoreCase("\u0001Ole10Native")) {

                    objects.add(
                            "OLE Stream : "
                                    + currentPath
                    );
                }
            }
        }
    }
}