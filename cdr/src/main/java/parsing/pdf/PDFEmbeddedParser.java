package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.EmbeddedObjectComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.apache.pdfbox.pdmodel.common.filespecification.PDFileSpecification;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFEmbeddedParser {

    // =========================================================
    // NEW IR EXTRACTION
    // =========================================================

    public List<EmbeddedObjectComponent>
    parseEmbeddedObjectComponents(
            Path file) throws IOException {

        List<EmbeddedObjectComponent> objects =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            PDDocumentNameDictionary names =
                    new PDDocumentNameDictionary(
                            document.getDocumentCatalog()
                    );

            var embeddedTree =
                    names.getEmbeddedFiles();

            if (embeddedTree == null) {
                return objects;
            }

            var namesMap =
                    embeddedTree.getNames();

            if (namesMap == null) {
                return objects;
            }

            int objectNumber = 1;

            for (var entry :
                    namesMap.entrySet()) {

                String name =
                        entry.getKey();

                PDFileSpecification specification =
                        entry.getValue();

                if (!(specification
                        instanceof PDComplexFileSpecification)) {

                    continue;
                }

                PDComplexFileSpecification fileSpec =
                        (PDComplexFileSpecification)
                                specification;

                PDEmbeddedFile embeddedFile =
                        fileSpec.getEmbeddedFile();

                if (embeddedFile == null) {
                    continue;
                }

                EmbeddedObjectComponent object =
                        new EmbeddedObjectComponent();

                object.setId(
                        "pdf_embedded_" +
                        objectNumber
                );

                object.setName(
                        name
                );

                object.setType(
                        embeddedFile.getSubtype() != null
                                ? embeddedFile.getSubtype()
                                : "application/octet-stream"
                );

                object.setData(
                        embeddedFile.toByteArray()
                );

                object.setActive(
                        true
                );

                objects.add(object);

                objectNumber++;
            }
        }

        return objects;
    }


    // =========================================================
    // OLD STRING EXTRACTION
    // =========================================================

    public List<String> parse(Path file)
            throws IOException {

        List<String> embeddedFiles =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            PDDocumentNameDictionary names =
                    new PDDocumentNameDictionary(
                            document.getDocumentCatalog()
                    );

            var embeddedTree =
                    names.getEmbeddedFiles();

            if (embeddedTree == null) {
                return embeddedFiles;
            }

            var namesMap =
                    embeddedTree.getNames();

            if (namesMap == null) {
                return embeddedFiles;
            }

            for (var entry :
                    namesMap.entrySet()) {

                String name =
                        entry.getKey();

                PDFileSpecification specification =
                        entry.getValue();

                if (specification
                        instanceof PDComplexFileSpecification) {

                    PDComplexFileSpecification fileSpec =
                            (PDComplexFileSpecification)
                                    specification;

                    PDEmbeddedFile embeddedFile =
                            fileSpec.getEmbeddedFile();

                    if (embeddedFile != null) {

                        embeddedFiles.add(
                                "Name : "
                                        + name
                                        + " | Size : "
                                        + embeddedFile.getSize()
                                        + " bytes"
                                        + " | MIME : "
                                        + embeddedFile
                                                .getSubtype()
                        );
                    }
                }
            }
        }

        return embeddedFiles;
    }
}