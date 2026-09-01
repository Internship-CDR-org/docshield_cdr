package parsing.xls;

import parsing.common.HyperlinkExtractor;


import model.common.HyperlinkComponent;

import org.apache.poi.hssf.usermodel.HSSFHyperlink;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XLSHyperlinkExtractor
        implements HyperlinkExtractor {

    @Override
    public List<HyperlinkComponent> extract(
            Path file) throws IOException {

        List<HyperlinkComponent> hyperlinks =
                new ArrayList<>();

        try (InputStream inputStream =
                     Files.newInputStream(file);
             HSSFWorkbook workbook =
                     new HSSFWorkbook(inputStream)) {

            int hyperlinkNumber = 1;

            for (Sheet sheet :
                    workbook) {

                for (Row row :
                        sheet) {

                    for (Cell cell :
                            row) {

                        HSSFHyperlink hyperlink =
                                (HSSFHyperlink)
                                        cell.getHyperlink();

                        if (hyperlink == null) {
                            continue;
                        }

                        HyperlinkComponent component =
                                new HyperlinkComponent();

                        component.setId(
                                "xls_hyperlink_" +
                                hyperlinkNumber
                        );

                        component.setDisplayText(
                                hyperlink.getLabel()
                        );

                        component.setTarget(
                                hyperlink.getAddress()
                        );

                        hyperlinks.add(component);

                        hyperlinkNumber++;
                    }
                }
            }
        }

        return hyperlinks;
    }
}