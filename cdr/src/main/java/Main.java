import identification.FileIdentifier;
import identification.FileInfo;

import model.common.DocumentModel;

import parsing.common.DocumentParser;
import parsing.common.ParserFactory;

import processing.common.CDRProcessor;
import processing.common.CDRResult;
import processing.docx.DOCXCDRProcessor;
import processing.pptx.PPTXCDRProcessor;
import processing.xlsx.XLSXCDRProcessor;

import reporting.ReportWriter;

import java.nio.file.Path;

public class Main {

    public static void main(String[] args) throws Exception {

        // =========================================================
        // COMMAND LINE
        // =========================================================

        if (args.length != 2) {

            System.out.println(
                    "Usage: ./run.sh <input-file> <output-file>"
            );

            return;
        }


        Path inputFile =
                Path.of(args[0]);

        Path outputFile =
                Path.of(args[1]);


        // =========================================================
        // FILE IDENTIFICATION
        // =========================================================

        FileIdentifier fileIdentifier =
                new FileIdentifier();

        FileInfo fileInfo =
                fileIdentifier.identify(
                        inputFile
                );


        // =========================================================
        // CDR PROCESSOR SELECTION
        // =========================================================

        CDRProcessor processor =
                createProcessor(
                        fileInfo
                );


        // =========================================================
        // TRUST BOUNDARY
        // =========================================================
        //
        // DOCX/PPTX/XLSX are untrusted package inputs. Do not send
        // them through the semantic POI parsers before sanitization.
        // The CDR package reader/security layer is the first parser
        // that touches these files.

        if (processor != null) {

            CDRResult result =
                    processor.process(
                            inputFile,
                            outputFile
                    );

            // Parse only the reconstructed/sanitized document for
            // semantic reporting. This keeps the unsafe original
            // outside the normal POI semantic parsing path.
            DocumentParser parser =
                    ParserFactory.getParser(
                            fileInfo.getFormat()
                    );

            DocumentModel model =
                    parser.parse(
                            outputFile
                    );

            model.setFileInfo(
                    fileInfo
            );

            ReportWriter reportWriter =
                    new ReportWriter();

            reportWriter.write(
                    model,
                    inputFile,
                    result
            );

            printSummary(
                    inputFile,
                    outputFile,
                    result
            );

            return;
        }


        // =========================================================
        // NON-OOXML FORMAT
        // =========================================================

        DocumentParser parser =
                ParserFactory.getParser(
                        fileInfo.getFormat()
                );

        DocumentModel model =
                parser.parse(
                        inputFile
                );

        model.setFileInfo(
                fileInfo
        );


        // =========================================================
        // LEGACY DOC VALIDATION
        // =========================================================

        if (parser instanceof parsing.doc.DOCParser) {

            parsing.doc.DOCParser docParser =
                    (parsing.doc.DOCParser) parser;

            parsing.doc.DOCParseResult parseResult =
                    docParser.getParseResult();

            parsing.doc.DOCExtractionValidator validator =
                    new parsing.doc.DOCExtractionValidator();

            boolean valid =
                    validator.validate(
                            parseResult
                    );

            System.out.println(
                    "DOC validation : " +
                    (valid ? "PASS" : "FAIL")
            );
        }


        ReportWriter reportWriter =
                new ReportWriter();

        reportWriter.write(
                model,
                inputFile
        );

        System.out.println();
        System.out.println(
                "=============================================="
        );
        System.out.println(
                "              DOCSHIELD CDR"
        );
        System.out.println(
                "=============================================="
        );
        System.out.println(
                "Input  : " + inputFile
        );
        System.out.println(
                "Report : output/reports/" +
                inputFile.getFileName() +
                "_CDR_Report.txt"
        );
        System.out.println(
                "=============================================="
        );

        return;
    }


    // =============================================================
    // PROCESSOR SELECTION
    // =============================================================

    private static CDRProcessor createProcessor(
            FileInfo fileInfo) {

        if (fileInfo == null ||
                fileInfo.getFormat() == null) {

            return null;
        }


        return switch (fileInfo.getFormat()) {

            case DOCX ->
                    new DOCXCDRProcessor();

            case PPTX ->
                    new PPTXCDRProcessor();

            case XLSX ->
                    new XLSXCDRProcessor();

            default ->
                    null;
        };
    }


    // =============================================================
    // UNIVERSAL SUMMARY
    // =============================================================

    private static void printSummary(
            Path inputFile,
            Path outputFile,
            CDRResult result) {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "              DOCSHIELD CDR"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "Input  : " +
                inputFile
        );

        System.out.println(
                "Output : " +
                outputFile
        );

        System.out.println();


        if (result.hasThreats()) {

            System.out.println(
                    "Threat : YES"
            );

            System.out.println(
                    "Type   : " +
                    result.getThreatSummary()
            );

            System.out.println(
                    "Level  : " +
                    result.getHighestSeverity()
            );

            System.out.println(
                    "Action : " +
                    (
                            result.isThreatRemoved()
                                    ? "REMOVED"
                                    : "NOT REMOVED"
                    )
            );

        } else {

            System.out.println(
                    "Threat : NO"
            );
        }


        System.out.println();

        System.out.println(
                "Reconstruction : " +
                (
                        result.isReconstructionSuccessful()
                                ? "SUCCESS"
                                : "FAILED"
                )
        );

        System.out.println(
                "Integrity      : " +
                (
                        result.isIntegrityPassed()
                                ? "PASS"
                                : "FAIL"
                )
        );

        System.out.println();


        System.out.println(
                "Report : output/reports/" +
                inputFile.getFileName() +
                "_CDR_Report.txt"
        );

        System.out.println(
                "=============================================="
        );
    }
}