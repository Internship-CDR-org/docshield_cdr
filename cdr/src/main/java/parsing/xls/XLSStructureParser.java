package parsing.xls;

import parsing.common.DocumentParser;

import model.common.StructureComponent;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Sheet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XLSStructureParser {

    public List<StructureComponent> parse(
            Path file) throws IOException {

        List<StructureComponent> structures =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSSFWorkbook workbook =
                     new HSSFWorkbook(inputStream)) {

            int index = 1;

            for (Sheet sheet :
                    workbook) {

                StructureComponent component =
                        new StructureComponent();

                component.setId(
                        "xls_sheet_" + index
                );

                component.setType(
                        "SHEET"
                );

                component.setName(
                        sheet.getSheetName()
                );

                component.setIndex(
                        index
                );

                structures.add(component);

                index++;
            }
        }

        return structures;
    }
}