package parsing.xls;

import parsing.common.DocumentParser;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XLSContentParser {

    public static class CellData {

        private final String sheetName;
        private final String cellAddress;
        private final String value;

        public CellData(
                String sheetName,
                String cellAddress,
                String value) {

            this.sheetName = sheetName;
            this.cellAddress = cellAddress;
            this.value = value;
        }

        public String getSheetName() {
            return sheetName;
        }

        public String getCellAddress() {
            return cellAddress;
        }

        public String getValue() {
            return value;
        }
    }


    public List<CellData> parseCells(
            Path file) throws IOException {

        List<CellData> content =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSSFWorkbook workbook =
                     new HSSFWorkbook(inputStream)) {

            DataFormatter formatter =
                    new DataFormatter();

            for (Sheet sheet :
                    workbook) {

                for (Row row :
                        sheet) {

                    for (Cell cell :
                            row) {

                        String value =
                                formatter.formatCellValue(
                                        cell
                                );

                        if (value != null &&
                                !value.isBlank()) {

                            content.add(
                                    new CellData(
                                            sheet.getSheetName(),
                                            cell.getAddress()
                                                    .formatAsString(),
                                            value
                                    )
                            );
                        }
                    }
                }
            }
        }

        return content;
    }
}