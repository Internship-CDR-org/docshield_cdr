package parsing.pdf;

import parsing.common.DocumentParser;

import model.common.StructureComponent;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class PDFFormParser {

    public List<String> parse(Path file)
            throws IOException {

        List<String> forms =
                new ArrayList<>();

        try (PDDocument document =
                     Loader.loadPDF(file.toFile())) {

            PDAcroForm acroForm =
                    document.getDocumentCatalog()
                            .getAcroForm();

            if (acroForm == null) {
                return forms;
            }

            for (PDField field :
                    acroForm.getFieldTree()) {

                String name =
                        field.getFullyQualifiedName();

                String type =
                        field.getFieldType();

                String value =
                        field.getValueAsString();

                forms.add(
                        "Field : "
                                + name
                                + " | Type : "
                                + type
                                + " | Value : "
                                + value
                );
            }
        }

        return forms;
    }

    public List<StructureComponent>
        parseStructureComponents(Path file)
                throws IOException {

        List<StructureComponent> components =
                new ArrayList<>();

        try (PDDocument document =
                        Loader.loadPDF(file.toFile())) {

                PDAcroForm acroForm =
                        document.getDocumentCatalog()
                                .getAcroForm();

                if (acroForm == null) {
                return components;
                }

                int index = 0;

                for (PDField field :
                        acroForm.getFieldTree()) {

                String name =
                        field.getFullyQualifiedName();

                String type =
                        field.getFieldType();

                StructureComponent component =
                        new StructureComponent();

                component.setId(
                        "pdf_form_" +
                        index
                );

                component.setType(
                        type != null
                                ? type
                                : "form-field"
                );

                component.setName(
                        name != null
                                ? name
                                : "unnamed-field"
                );

                component.setIndex(
                        index
                );

                components.add(component);

                index++;
                }
        }

        return components;
        }
}