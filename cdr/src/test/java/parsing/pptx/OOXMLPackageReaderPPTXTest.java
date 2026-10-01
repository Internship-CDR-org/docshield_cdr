package parsing.pptx;
import parsing.ooxml.OOXMLPackageReader;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import java.nio.file.Path;

public class OOXMLPackageReaderPPTXTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java parsing.pptx.OOXMLPackageReaderTest <file.pptx>"
            );

            System.exit(1);
        }

        Path pptxPath =
                Path.of(args[0]);

        try {

            System.out.println();
            System.out.println(
                    "=============================================="
            );
            System.out.println(
                    "        PPTX PACKAGE READER TEST"
            );
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "Input : " + pptxPath
            );

            System.out.println();


            // =================================================
            // READ PACKAGE
            // =================================================

            OOXMLPackageReader reader =
                    new OOXMLPackageReader();

            OOXMLPackage pptxPackage =
                    reader.read(
                            pptxPath
                    );


            // =================================================
            // BASIC PACKAGE INFORMATION
            // =================================================

            System.out.println(
                    "========== PACKAGE SUMMARY =========="
            );

            System.out.println(
                    "Total parts         : " +
                    pptxPackage.getPartCount()
            );

            System.out.println(
                    "Total relationships  : " +
                    pptxPackage.getRelationshipCount()
            );

            System.out.println(
                    "Content types       : " +
                    pptxPackage
                            .getContentTypes()
                            .size()
            );

            System.out.println();


            // =================================================
            // PART INVENTORY
            // =================================================

            int slides = 0;
            int layouts = 0;
            int masters = 0;
            int themes = 0;
            int notesSlides = 0;
            int notesMasters = 0;
            int media = 0;
            int fonts = 0;
            int charts = 0;
            int embeddings = 0;
            int activeX = 0;
            int vba = 0;


            System.out.println(
                    "========== PART INVENTORY =========="
            );


            for (OOXMLPart part :
                    pptxPackage.getParts()) {

                if (part == null ||
                        part.getPartName() == null) {

                    continue;
                }


                String name =
                        part.getPartName();


                System.out.println(
                        name
                );


                String lower =
                        name.toLowerCase();


                if (lower.startsWith(
                        "ppt/slides/slide"
                ) &&
                        lower.endsWith(".xml")) {

                    slides++;
                }


                if (lower.startsWith(
                        "ppt/slidelayouts/"
                ) &&
                        lower.endsWith(".xml")) {

                    layouts++;
                }


                if (lower.startsWith(
                        "ppt/slidemasters/"
                ) &&
                        lower.endsWith(".xml")) {

                    masters++;
                }


                if (lower.startsWith(
                        "ppt/theme/"
                ) &&
                        lower.endsWith(".xml")) {

                    themes++;
                }


                if (lower.startsWith(
                        "ppt/notesslides/"
                ) &&
                        lower.endsWith(".xml")) {

                    notesSlides++;
                }


                if (lower.startsWith(
                        "ppt/notesmasters/"
                ) &&
                        lower.endsWith(".xml")) {

                    notesMasters++;
                }


                if (lower.startsWith(
                        "ppt/media/"
                )) {

                    media++;
                }


                if (lower.startsWith(
                        "ppt/fonts/"
                )) {

                    fonts++;
                }


                if (lower.startsWith(
                        "ppt/charts/"
                )) {

                    charts++;
                }


                if (lower.startsWith(
                        "ppt/embeddings/"
                )) {

                    embeddings++;
                }


                if (lower.startsWith(
                        "ppt/activex/"
                )) {

                    activeX++;
                }


                if (lower.contains(
                        "vbaproject"
                )) {

                    vba++;
                }
            }


            System.out.println();


            // =================================================
            // CLASSIFIED COUNTS
            // =================================================

            System.out.println(
                    "========== CLASSIFIED COUNTS =========="
            );

            System.out.println(
                    "Slides              : " +
                    slides
            );

            System.out.println(
                    "Slide layouts       : " +
                    layouts
            );

            System.out.println(
                    "Slide masters       : " +
                    masters
            );

            System.out.println(
                    "Themes              : " +
                    themes
            );

            System.out.println(
                    "Notes slides        : " +
                    notesSlides
            );

            System.out.println(
                    "Notes masters       : " +
                    notesMasters
            );

            System.out.println(
                    "Media               : " +
                    media
            );

            System.out.println(
                    "Fonts               : " +
                    fonts
            );

            System.out.println(
                    "Charts              : " +
                    charts
            );

            System.out.println(
                    "Embeddings          : " +
                    embeddings
            );

            System.out.println(
                    "ActiveX             : " +
                    activeX
            );

            System.out.println(
                    "VBA                 : " +
                    vba
            );

            System.out.println();


            // =================================================
            // RELATIONSHIP INVENTORY
            // =================================================

            System.out.println(
                    "========== RELATIONSHIPS =========="
            );


            for (OOXMLRelationship relationship :
                    pptxPackage.getRelationships()) {

                System.out.println(
                        relationship
                );
            }


            System.out.println();


            // =================================================
            // CONTENT TYPES
            // =================================================

            System.out.println(
                    "========== CONTENT TYPES =========="
            );


            for (var entry :
                    pptxPackage
                            .getContentTypes()
                            .entrySet()) {

                System.out.println(
                        entry.getKey() +
                        " -> " +
                        entry.getValue()
                );
            }


            System.out.println();


            // =================================================
            // COMPLETE
            // =================================================

            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "PACKAGE READER TEST COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "PACKAGE READER TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}