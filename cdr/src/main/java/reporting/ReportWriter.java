package reporting;

import model.common.DocumentModel;
import model.common.MetadataModel;
import model.common.ImageComponent;
import model.common.EmbeddedObjectComponent;
import model.common.StructureComponent;
import model.common.HyperlinkComponent;
import model.common.ThreatComponent;
import model.common.TextComponent;

import java.util.Map;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ReportWriter {

    public void write(
            DocumentModel model,
            Path inputFile)
            throws IOException {

        write(
                model,
                inputFile,
                null
        );
        }

        /**
         * Writes the semantic analysis report together with
         * the CDR processing results.
         */
        public void write(
                DocumentModel model,
                Path inputFile,
                processing.common.CDRResult result)
                throws IOException {

                Path outputDirectory =
                        Paths.get(
                                "output",
                                "reports"
                        );

                Files.createDirectories(
                        outputDirectory
                );

                String fileName =
                        inputFile.getFileName()
                                .toString();

                Path reportFile =
                        outputDirectory.resolve(
                                fileName +
                                "_CDR_Report.txt"
                        );

                try (
                        BufferedWriter writer =
                                Files.newBufferedWriter(
                                        reportFile
                                )
                ) {

                writer.write(
                        "============================================================"
                );
                writer.newLine();

                writer.write(
                        "                    CDR ANALYSIS REPORT"
                );
                writer.newLine();

                writer.write(
                        "============================================================"
                );
                writer.newLine();
                writer.newLine();


                // =====================================================
                // FILE IDENTIFICATION
                // =====================================================

                writeIdentification(
                        writer,
                        model
                );


                // =====================================================
                // METADATA
                // =====================================================

                writeMetadata(
                        writer,
                        model.getMetadata()
                );


                // =====================================================
                // COMMON IR
                // =====================================================

                writeTextComponents(
                        writer,
                        model.getTextComponents()
                );

                writeImageComponents(
                        writer,
                        model.getImageComponents()
                );

                writeEmbeddedObjectComponents(
                        writer,
                        model.getEmbeddedObjectComponents()
                );

                writeStructureComponents(
                        writer,
                        model.getStructureComponents()
                );

                writeHyperlinkComponents(
                        writer,
                        model.getHyperlinkComponents()
                );

                writeThreatComponents(
                        writer,
                        model.getThreatComponents()
                );


                // =====================================================
                // SECURITY FINDINGS
                // =====================================================

                writer.write(
                        "SECURITY FINDINGS"
                );
                writer.newLine();

                writer.write(
                        "------------------------------------------------------------"
                );
                writer.newLine();


                if (result == null ||
                        result.getFindings() == null ||
                        result.getFindings().isEmpty()) {

                        writer.write(
                                "Threats detected : NO"
                        );
                        writer.newLine();

                } else {

                        writer.write(
                                "Threats detected : YES"
                        );
                        writer.newLine();

                        for (
                                threat.common.SecurityFinding finding :
                                result.getFindings()
                        ) {

                        if (finding == null) {
                                continue;
                        }

                        writer.newLine();

                        writer.write(
                                "Classification : " +
                                finding.getClassification()
                        );
                        writer.newLine();

                        writer.write(
                                "Type           : " +
                                finding.getType()
                        );
                        writer.newLine();

                        writer.write(
                                "Severity       : " +
                                finding.getSeverity()
                        );
                        writer.newLine();

                        writer.write(
                                "Part           : " +
                                finding.getPartName()
                        );
                        writer.newLine();

                        writer.write(
                                "Source Part    : " +
                                finding.getSourcePart()
                        );
                        writer.newLine();

                        writer.write(
                                "Relationship ID: " +
                                finding.getRelationshipId()
                        );
                        writer.newLine();

                        writer.write(
                                "Evidence       : " +
                                finding.getEvidence()
                        );
                        writer.newLine();

                        writer.write(
                                "Description    : " +
                                finding.getDescription()
                        );
                        writer.newLine();

                        writer.write(
                                "Recommended    : " +
                                finding.getRecommendedAction()
                        );
                        writer.newLine();
                        }
                }


                writer.newLine();


                // =====================================================
                // SANITIZATION
                // =====================================================

                writer.write(
                        "SANITIZATION"
                );
                writer.newLine();

                writer.write(
                        "------------------------------------------------------------"
                );
                writer.newLine();


                if (result == null ||
                        result.getActions() == null ||
                        result.getActions().isEmpty()) {

                        writer.write(
                                "Actions : NONE"
                        );
                        writer.newLine();

                } else {

                        writer.write(
                                "Actions : " +
                                result.getActions().size()
                        );
                        writer.newLine();

                        for (String action :
                                result.getActions()) {

                        writer.write(
                                "  - " +
                                action
                        );
                        writer.newLine();
                        }
                }


                writer.newLine();


                // =====================================================
                // RECONSTRUCTION
                // =====================================================

                writer.write(
                        "RECONSTRUCTION"
                );
                writer.newLine();

                writer.write(
                        "------------------------------------------------------------"
                );
                writer.newLine();

                if (result == null) {

                        writer.write(
                                "Status : NOT AVAILABLE"
                        );
                        writer.newLine();

                } else {

                        writer.write(
                                "Status    : " +
                                (
                                        result.isReconstructionSuccessful()
                                                ? "SUCCESS"
                                                : "FAILED"
                                )
                        );
                        writer.newLine();

                        writer.write(
                                "Integrity : " +
                                (
                                        result.isIntegrityPassed()
                                                ? "PASS"
                                                : "FAIL"
                                )
                        );
                        writer.newLine();
                }


                writer.newLine();

                writer.write(
                        "============================================================"
                );
                writer.newLine();
                }

                System.out.println(
                        "CDR report created: " +
                        reportFile
                );
        }


    // =============================================================
    // FILE IDENTIFICATION
    // =============================================================

    private void writeIdentification(
            BufferedWriter writer,
            DocumentModel model)
            throws IOException {

        writer.write("FILE IDENTIFICATION");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (model.getFileInfo() == null) {

            writer.write(
                    "No identification information available."
            );
            writer.newLine();
            writer.newLine();

            return;
        }


        writer.write(
                "File Name       : " +
                model.getFileInfo().getFileName()
        );
        writer.newLine();


        writer.write(
                "File Size       : " +
                model.getFileInfo().getFileSize() +
                " bytes"
        );
        writer.newLine();


        writer.write(
                "Extension       : " +
                model.getFileInfo().getExtension()
        );
        writer.newLine();


        writer.write(
                "MIME Type       : " +
                model.getFileInfo().getMimeType()
        );
        writer.newLine();


        writer.write(
                "Format          : " +
                model.getFileInfo().getFormat()
        );
        writer.newLine();


        writer.write(
                "SHA-256         : " +
                model.getFileInfo().getSha256()
        );
        writer.newLine();


        writer.write(
                "Valid           : " +
                model.getFileInfo().isValid()
        );
        writer.newLine();


        writer.write(
                "Extension Match : " +
                model.getFileInfo().isExtensionMatch()
        );
        writer.newLine();

        writer.newLine();
    }


    // =============================================================
    // TEXT COMPONENTS
    // =============================================================

    private void writeTextComponents(
            BufferedWriter writer,
            java.util.List<TextComponent> components)
            throws IOException {

        writer.write("IR TEXT");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();

        if (components.isEmpty()) {

                writer.write(
                        "No data extracted."
                );
                writer.newLine();

        } else {

                for (TextComponent component :
                        components) {

                writer.write(
                        "ID       : " +
                        component.getId()
                );
                writer.newLine();

                writer.write(
                        "Page     : " +
                        component.getPageNumber()
                );
                writer.newLine();

                writer.write(
                        "Position : (" +
                        component.getX() +
                        ", " +
                        component.getY() +
                        ")"
                );
                writer.newLine();

                writer.write(
                        "Size     : " +
                        component.getWidth() +
                        " x " +
                        component.getHeight()
                );
                writer.newLine();

                writer.write(
                        "Font     : " +
                        component.getFontName()
                );
                writer.newLine();

                writer.write(
                        "FontSize : " +
                        component.getFontSize()
                );
                writer.newLine();

                writer.write(
                        "Alignment: " +
                        component.getAlignment()
                );
                writer.newLine();

                writer.write(
                        "Text     : " +
                        component.getText()
                );
                writer.newLine();

                writer.newLine();
                }
        }

        writer.newLine();
    }


    // =============================================================
    // IMAGE COMPONENTS
    // =============================================================

    private void writeImageComponents(
            BufferedWriter writer,
            java.util.List<ImageComponent> components)
            throws IOException {

        writer.write("IR IMAGES");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (components.isEmpty()) {

            writer.write(
                    "No data extracted."
            );
            writer.newLine();

        } else {

            for (ImageComponent component :
                    components) {

                writer.write(
                        component.getId()
                                + " : "
                                + component.getFileName()
                                + " | MIME : "
                                + component.getMimeType()
                                + " | Size : "
                                + component.getWidth()
                                + "x"
                                + component.getHeight()
                                + " | Bytes : "
                                + (
                                    component.getData() == null
                                        ? 0
                                        : component.getData().length
                                )
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }


    // =============================================================
    // EMBEDDED OBJECT COMPONENTS
    // =============================================================

    private void writeEmbeddedObjectComponents(
            BufferedWriter writer,
            java.util.List<EmbeddedObjectComponent> components)
            throws IOException {

        writer.write(
                "IR EMBEDDED OBJECTS"
        );
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (components.isEmpty()) {

            writer.write(
                    "No data extracted."
            );
            writer.newLine();

        } else {

            for (EmbeddedObjectComponent component :
                    components) {

                writer.write(
                        component.getId()
                                + " : "
                                + component.getName()
                                + " | Type : "
                                + component.getType()
                                + " | Bytes : "
                                + (
                                    component.getData() == null
                                        ? 0
                                        : component.getData().length
                                )
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }


    // =============================================================
    // STRUCTURE COMPONENTS
    // =============================================================

    private void writeStructureComponents(
            BufferedWriter writer,
            java.util.List<StructureComponent> components)
            throws IOException {

        writer.write("IR STRUCTURE");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (components.isEmpty()) {

            writer.write(
                    "No data extracted."
            );
            writer.newLine();

        } else {

            for (StructureComponent component :
                    components) {

                writer.write(
                        component.getId()
                                + " : "
                                + component.getType()
                                + " | Name : "
                                + component.getName()
                                + " | Index : "
                                + component.getIndex()
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }


    // =============================================================
    // HYPERLINK COMPONENTS
    // =============================================================

    private void writeHyperlinkComponents(
            BufferedWriter writer,
            java.util.List<HyperlinkComponent> components)
            throws IOException {

        writer.write("IR HYPERLINKS");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (components.isEmpty()) {

            writer.write(
                    "No data extracted."
            );
            writer.newLine();

        } else {

            for (HyperlinkComponent component :
                    components) {

                writer.write(
                        component.getId()
                                + " : "
                                + component.getDisplayText()
                                + " -> "
                                + component.getTarget()
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }


    // =============================================================
    // THREAT COMPONENTS
    // =============================================================

    private void writeThreatComponents(
            BufferedWriter writer,
            java.util.List<ThreatComponent> components)
            throws IOException {

        writer.write("IR THREATS");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();


        if (components.isEmpty()) {

            writer.write(
                    "No data extracted."
            );
            writer.newLine();

        } else {

            for (ThreatComponent component :
                    components) {

                writer.write(
                        component.getId()
                                + " : "
                                + component.getCategory()
                                + " | Rule : "
                                + component.getRuleId()
                                + " | Severity : "
                                + component.getSeverity()
                                + " | Action : "
                                + component.getAction()
                                + " | Description : "
                                + component.getDescription()
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }


    // =============================================================
    // METADATA
    // =============================================================

    private void writeMetadata(
            BufferedWriter writer,
            MetadataModel metadata)
            throws IOException {

        writer.write("METADATA");
        writer.newLine();

        writer.write(
                "------------------------------------------------------------"
        );
        writer.newLine();

        writer.newLine();


        // ---------------------------------------------------------
        // CORE METADATA
        // ---------------------------------------------------------

        writer.write("[CORE METADATA]");
        writer.newLine();


        if (metadata.getCoreMetadata().isEmpty()) {

            writer.write(
                    "No core metadata found."
            );
            writer.newLine();

        } else {

            for (Map.Entry<String, String> entry :
                    metadata.getCoreMetadata().entrySet()) {

                writer.write(
                        entry.getKey()
                                + " : "
                                + entry.getValue()
                );

                writer.newLine();
            }
        }

        writer.newLine();


        // ---------------------------------------------------------
        // APPLICATION METADATA
        // ---------------------------------------------------------

        writer.write(
                "[APPLICATION METADATA]"
        );
        writer.newLine();


        if (metadata.getApplicationMetadata().isEmpty()) {

            writer.write(
                    "No application metadata found."
            );
            writer.newLine();

        } else {

            for (Map.Entry<String, String> entry :
                    metadata.getApplicationMetadata().entrySet()) {

                writer.write(
                        entry.getKey()
                                + " : "
                                + entry.getValue()
                );

                writer.newLine();
            }
        }

        writer.newLine();


        // ---------------------------------------------------------
        // CUSTOM METADATA
        // ---------------------------------------------------------

        writer.write(
                "[CUSTOM METADATA]"
        );
        writer.newLine();


        if (metadata.getCustomMetadata().isEmpty()) {

            writer.write(
                    "No custom metadata parsed yet."
            );
            writer.newLine();

        } else {

            for (Map.Entry<String, String> entry :
                    metadata.getCustomMetadata().entrySet()) {

                writer.write(
                        entry.getKey()
                                + " : "
                                + entry.getValue()
                );

                writer.newLine();
            }
        }

        writer.newLine();
    }
}