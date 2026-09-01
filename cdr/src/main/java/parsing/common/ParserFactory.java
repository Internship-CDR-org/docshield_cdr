package parsing.common;

import parsing.doc.DOCParser;
import parsing.docx.DOCXParser;
import parsing.pdf.PDFParser;
import parsing.ppt.PPTParser;
import parsing.pptx.PPTXParser;
import parsing.rtf.RTFParser;
import parsing.xls.XLSParser;
import parsing.xlsx.XLSXParser;

import identification.Format;

public class ParserFactory {
    public static DocumentParser getParser(Format format) {
        switch (format) {
            case DOCX:
                return new DOCXParser();
            case PDF:
                return new PDFParser();
            case DOC:
                return new DOCParser();
            case PPT:
                return new PPTParser();
            case PPTX:
                return new PPTXParser();
            case XLS:
                return new XLSParser();
            case XLSX:
                return new XLSXParser();
            case RTF:
                return new RTFParser();
            default:
                throw new IllegalArgumentException("No Parser Available For " + format);
        }
    }
}