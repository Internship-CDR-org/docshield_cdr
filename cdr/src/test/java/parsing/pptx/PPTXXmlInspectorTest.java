package parsing.pptx;
import parsing.ooxml.OOXMLPackageReader;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;

import java.nio.file.Path;
import java.util.List;

public class PPTXXmlInspectorTest {

    public static void main(String[] args) {

        if (args.length != 1) {

            System.err.println(
                    "Usage: java parsing.pptx.PPTXXmlInspectorTest <file.pptx>"
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
                    "          PPTX XML INSPECTOR TEST"
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
            // CREATE XML INSPECTOR
            // =================================================

            PPTXXmlInspector inspector =
                    new PPTXXmlInspector();


            // =================================================
            // INSPECT SELECTED IMPORTANT XML PARTS
            // =================================================

            String[] partsToInspect = {

                    "ppt/presentation.xml",

                    "ppt/slides/slide1.xml",

                    "ppt/slides/slide2.xml",

                    "ppt/slideLayouts/slideLayout1.xml",

                    "ppt/slideLayouts/slideLayout2.xml",

                    "ppt/slideMasters/slideMaster1.xml",

                    "ppt/theme/theme1.xml",

                    "ppt/theme/theme2.xml",

                    "ppt/presProps.xml",

                    "ppt/viewProps.xml",

                    "ppt/tableStyles.xml"
            };


            for (String partName :
                    partsToInspect) {

                System.out.println();
                System.out.println(
                        "----------------------------------------------"
                );

                System.out.println(
                        "PART: " + partName
                );

                System.out.println(
                        "----------------------------------------------"
                );


                OOXMLPart part =
                        pptxPackage.getPart(
                                partName
                        );


                if (part == null) {

                    System.out.println(
                            "NOT FOUND"
                    );

                    continue;
                }


                PPTXXmlInspector.XmlInspectionResult result =
                        inspector.inspect(
                                part
                        );


                // -------------------------------------------------
                // Basic parsing information
                // -------------------------------------------------

                System.out.println(
                        "Parsed          : " +
                        result.isXmlParsed()
                );


                System.out.println(
                        "Root element    : " +
                        result.getRootElement()
                );


                if (!result.isXmlParsed()) {

                    System.out.println(
                            "Parse error     : " +
                            result.getParseError()
                    );

                    continue;
                }


                // -------------------------------------------------
                // Namespaces
                // -------------------------------------------------

                System.out.println();
                System.out.println(
                        "Namespaces:"
                );


                for (String namespace :
                        result.getNamespaces()) {

                    System.out.println(
                            "  " + namespace
                    );
                }


                // -------------------------------------------------
                // Element names
                // -------------------------------------------------

                System.out.println();
                System.out.println(
                        "Elements:"
                );


                for (String element :
                        result.getElementNames()) {

                    System.out.println(
                            "  " + element
                    );
                }


                // -------------------------------------------------
                // Attribute names
                // -------------------------------------------------

                System.out.println();
                System.out.println(
                        "Attributes:"
                );


                for (String attribute :
                        result.getAttributeNames()) {

                    System.out.println(
                            "  " + attribute
                    );
                }


                // -------------------------------------------------
                // External-reference evidence
                // -------------------------------------------------

                System.out.println();
                System.out.println(
                        "Potential external references:"
                );


                List<String> references =
                        result.getExternalReferences();


                if (references.isEmpty()) {

                    System.out.println(
                            "  None detected"
                    );

                } else {

                    for (String reference :
                            references) {

                        System.out.println(
                                "  " + reference
                        );
                    }
                }
            }


            System.out.println();
            System.out.println(
                    "=============================================="
            );

            System.out.println(
                    "XML INSPECTION COMPLETE"
            );

            System.out.println(
                    "=============================================="
            );


        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "XML INSPECTOR TEST FAILED"
            );

            e.printStackTrace();

            System.exit(1);
        }
    }
}