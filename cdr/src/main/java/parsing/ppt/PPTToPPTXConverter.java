package parsing.ppt;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class PPTToPPTXConverter {

    public Path convert(Path pptFile)
            throws IOException {

        if (pptFile == null ||
                !Files.exists(pptFile)) {

            throw new IOException(
                    "PPT file does not exist."
            );
        }

        Path outputDirectory =
                Files.createTempDirectory(
                        "docshield_pptx_"
                );

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "libreoffice",
                        "--headless",
                        "--convert-to",
                        "pptx",
                        "--outdir",
                        outputDirectory.toString(),
                        pptFile.toAbsolutePath().toString()
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
            // Process result will be checked below.
        }

        try {

            int exitCode =
                    process.waitFor();

            if (exitCode != 0) {

                throw new IOException(
                        "LibreOffice PPT → PPTX conversion failed. "
                        + "Exit code: " +
                        exitCode
                );
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new IOException(
                    "PPT → PPTX conversion interrupted.",
                    e
            );
        }

        String originalName =
                pptFile.getFileName().toString();

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
                        baseName + ".pptx"
                );

        if (!Files.exists(convertedFile)) {

            throw new IOException(
                    "LibreOffice reported success, "
                    + "but the converted PPTX was not found."
            );
        }

        return convertedFile;
    }
}