package parsing.doc;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class DOCToDOCXConverter {

    public Path convert(Path docFile)
            throws IOException {

        if (docFile == null ||
                !Files.exists(docFile)) {

            throw new IOException(
                    "DOC file does not exist."
            );
        }

        Path outputDirectory =
                Files.createTempDirectory(
                        "docshield_docx_"
                );

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "libreoffice",
                        "--headless",
                        "--convert-to",
                        "docx",
                        "--outdir",
                        outputDirectory.toString(),
                        docFile.toAbsolutePath().toString()
                );

        processBuilder.redirectErrorStream(true);

        Process process =
                processBuilder.start();

        try {
            process.getInputStream()
                    .transferTo(
                            System.out
                    );
        } catch (IOException ignored) {
            // Process result will still be checked below.
        }

        try {

            int exitCode =
                    process.waitFor();

            if (exitCode != 0) {

                throw new IOException(
                        "LibreOffice conversion failed. "
                        + "Exit code: "
                        + exitCode
                );
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new IOException(
                    "LibreOffice conversion interrupted.",
                    e
            );
        }

        String originalName =
                docFile.getFileName().toString();

        int extensionIndex =
                originalName.lastIndexOf('.');

        String baseName =
                extensionIndex > 0
                        ? originalName.substring(
                                0,
                                extensionIndex
                        )
                        : originalName;

        Path convertedFile =
                outputDirectory.resolve(
                        baseName + ".docx"
                );

        if (!Files.exists(convertedFile)) {

            throw new IOException(
                    "LibreOffice reported success, "
                    + "but the converted DOCX was not found."
            );
        }

        return convertedFile;
    }
}