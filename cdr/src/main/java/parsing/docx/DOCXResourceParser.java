package parsing.docx;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class DOCXResourceParser {

    public List<String> parseImages(Path file)
            throws IOException {

        List<String> images =
                new ArrayList<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            var entries =
                    zipFile.entries();

            while (entries.hasMoreElements()) {

                ZipEntry entry =
                        entries.nextElement();

                if (entry.isDirectory()) {
                    continue;
                }

                String name =
                        entry.getName();

                if (name.startsWith("word/media/")) {

                    images.add(name);
                }
            }
        }

        return images;
    }

    public List<String> parseEmbeddedObjects(
            Path file)
            throws IOException {

        List<String> objects =
                new ArrayList<>();

        try (ZipFile zipFile =
                     new ZipFile(file.toFile())) {

            var entries =
                    zipFile.entries();

            while (entries.hasMoreElements()) {

                ZipEntry entry =
                        entries.nextElement();

                if (entry.isDirectory()) {
                    continue;
                }

                String name =
                        entry.getName();

                if (name.startsWith(
                        "word/embeddings/")) {

                    objects.add(name);
                }
            }
        }

        return objects;
    }
}