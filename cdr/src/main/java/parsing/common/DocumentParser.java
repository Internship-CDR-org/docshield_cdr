package parsing.common;

import model.common.DocumentModel;

import java.io.IOException;
import java.nio.file.Path;

public interface DocumentParser {

    DocumentModel parse(Path file) throws IOException;

}