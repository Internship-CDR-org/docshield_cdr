package parsing.xlsx;

import parsing.common.DocumentParser;

import model.common.DocumentModel;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class XLSXParser implements DocumentParser {

    @Override
    public DocumentModel parse(Path file)
            throws IOException {

        DocumentModel model =
                new DocumentModel();

        XLSXContentParser contentParser =
                new XLSXContentParser();

        List<String> cells =
                contentParser.parseCells(file);

        for (String cell : cells) {

            model.addContent(cell);
        }

        return model;
    }
}   