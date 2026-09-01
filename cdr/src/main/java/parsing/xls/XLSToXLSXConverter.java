package parsing.xls;

import parsing.common.DocumentParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class XLSToXLSXConverter {

    public Path convert(Path xlsFile)
            throws IOException {

        if (xlsFile == null ||
                !Files.exists(xlsFile)) {

            throw new IOException(
                    "XLS file does not exist."
            );
        }

        Path outputDirectory =
                Files.createTempDirectory(
                        "docshield_xlsx_"
                );

        ProcessBuilder processBuilder =
                new ProcessBuilder(
                        "libreoffice",
                        "--headless",
                        "--convert-to",
                        "xlsx",
                        "--outdir",
                        outputDirectory.toString(),
                        xlsFile.toAbsolutePath().toString()
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
            // Conversion result is checked below.
        }

        try {

            int exitCode =
                    process.waitFor();

            if (exitCode != 0) {

                throw new IOException(
                        "LibreOffice XLS → XLSX conversion failed. "
                        + "Exit code: " +
                        exitCode
                );
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new IOException(
                    "XLS → XLSX conversion interrupted.",
                    e
            );
        }

        String originalName =
                xlsFile.getFileName().toString();

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
                        baseName + ".xlsx"
                );

        if (!Files.exists(convertedFile)) {

            throw new IOException(
                    "LibreOffice reported success, "
                    + "but the converted XLSX was not found."
            );
        }

        return convertedFile;
    }
}