package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.StructureComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFStructureParser {

    public List<String> parse(Path file)
            throws IOException {

        List<String> structure =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            int pageCount =
                    document.getNumberOfPages();

            structure.add(
                    "Page Count : " + pageCount
            );

            for (int i = 0; i < pageCount; i++) {

                var page =
                        document.getPage(i);

                structure.add(
                        "Page " + (i + 1)
                                + " : "
                                + page.getMediaBox()
                );
            }
        }

        return structure;
    }

    public List<StructureComponent>
        parseStructureComponents(Path file)
                throws IOException {

        List<StructureComponent> components =
                new ArrayList<>();

        try (PDDocument document =
                        Loader.loadPDF(file.toFile())) {

                int pageCount =
                        document.getNumberOfPages();

                // Document-level structure
                StructureComponent documentComponent =
                        new StructureComponent();

                documentComponent.setId(
                        "pdf_document_structure"
                );

                documentComponent.setType(
                        "document"
                );

                documentComponent.setName(
                        "PDF"
                );

                documentComponent.setIndex(
                        0
                );

                components.add(
                        documentComponent
                );


                // Page-level structure
                for (int i = 0;
                i < pageCount;
                i++) {

                StructureComponent pageComponent =
                        new StructureComponent();

                pageComponent.setId(
                        "pdf_page_" +
                        (i + 1)
                );

                pageComponent.setType(
                        "page"
                );

                pageComponent.setName(
                        "Page " +
                        (i + 1)
                );

                pageComponent.setIndex(
                        i
                );

                components.add(
                        pageComponent
                );
                }
        }

        return components;
        }
}