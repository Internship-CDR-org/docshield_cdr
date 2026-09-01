package sanitization.pdf;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import threat.common.SecurityFinding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * PDF CDR sanitizer. It mutates the loaded PDF object graph and the caller
 * writes a completely new PDF. Active actions and arbitrary attached payloads
 * are disarmed; ordinary page content and approved hyperlinks are retained.
 */
public final class PDFThreatSanitizer {
    private static final Set<String> BLOCKING_ACTIONS = Set.of(
            "JAVASCRIPT", "LAUNCH", "GOTOR", "GOTOE", "SUBMITFORM",
            "IMPORTDATA", "RENDITION", "MOVIE", "SOUND", "RICHMEDIAEXECUTE"
    );
    private static final Set<String> ACTIVE_ANNOTATIONS = Set.of(
            "FILEATTACHMENT", "RICHMEDIA", "3D", "MOVIE", "SOUND", "SCREEN"
    );

    public List<String> sanitize(PDDocument document, List<SecurityFinding> findings) {
        if (document == null || document.getDocumentCatalog() == null) return Collections.emptyList();
        List<String> actions = new ArrayList<>();
        Set<COSBase> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        COSDictionary catalog = document.getDocumentCatalog().getCOSObject();

        // Name trees containing active JavaScript or arbitrary embedded files are
        // removed as a whole. Other name trees (Dests, AP, etc.) remain intact.
        COSBase namesBase = catalog.getDictionaryObject(COSName.NAMES);
        if (namesBase instanceof COSDictionary names) {
            if (names.getDictionaryObject(COSName.getPDFName("JavaScript")) != null) {
                names.removeItem(COSName.getPDFName("JavaScript"));
                actions.add("Removed document JavaScript name tree.");
            }
            if (names.getDictionaryObject(COSName.getPDFName("EmbeddedFiles")) != null) {
                names.removeItem(COSName.getPDFName("EmbeddedFiles"));
                actions.add("Removed document embedded-file name tree.");
            }
        }

        removeIfDangerousAction(catalog, COSName.OPEN_ACTION, actions, "catalog/OpenAction");
        if (catalog.getDictionaryObject(COSName.AA) != null) {
            catalog.removeItem(COSName.AA);
            actions.add("Removed document-level additional actions.");
        }

        // XFA is an active XML form mechanism. Ordinary AcroForm fields are retained.
        if (catalog.getDictionaryObject(COSName.ACRO_FORM) instanceof COSDictionary form) {
            if (form.getDictionaryObject(COSName.getPDFName("XFA")) != null) {
                form.removeItem(COSName.getPDFName("XFA"));
                actions.add("Removed XFA form content.");
            }
            // A CDR rewrite invalidates existing signatures. Remove signature
            // fields themselves, not merely their values, so the reconstructed
            // document cannot advertise a stale signature field.
            COSBase fields = form.getDictionaryObject(COSName.getPDFName("Fields"));
            if (fields instanceof COSArray fieldArray) {
                removeSignatureFields(fieldArray, actions, "catalog/AcroForm/Fields");
            }
        }

        // Page annotations need special handling because an active annotation is
        // a security boundary; merely deleting its action can leave an attachment,
        // RichMedia object, or 3D object accessible through the page.
        int pageNumber = 1;
        for (PDPage page : document.getPages()) {
            if (page != null) {
                sanitizePageAnnotations(page, pageNumber, actions, visited);
            }
            pageNumber++;
        }

        sanitizeDictionary(catalog, "catalog", actions, visited);
        return actions;
    }

    private void sanitizePageAnnotations(PDPage page, int pageNumber,
                                         List<String> actions, Set<COSBase> visited) {
        COSArray annotations = page.getCOSObject().getCOSArray(COSName.ANNOTS);
        if (annotations == null) return;

        for (int i = annotations.size() - 1; i >= 0; i--) {
            COSBase base = annotations.getObject(i);
            if (!(base instanceof COSDictionary annotation)) continue;
            COSBase subtype = annotation.getDictionaryObject(COSName.SUBTYPE);
            if (isSignatureFieldOrWidget(annotation)) {
                annotations.remove(i);
                actions.add("Removed signature field/widget from page " + pageNumber + ".");
                continue;
            }
            if (subtype instanceof COSName name &&
                    ACTIVE_ANNOTATIONS.contains(name.getName().toUpperCase(Locale.ROOT))) {
                annotations.remove(i);
                actions.add("Removed active /" + name.getName() + " annotation from page " + pageNumber + ".");
                continue;
            }
            sanitizeDictionary(annotation, "page " + pageNumber + "/Annots[" + i + "]", actions, visited);
        }
    }

    private void removeSignatureFields(COSArray fields, List<String> actions, String location) {
        for (int i = fields.size() - 1; i >= 0; i--) {
            COSBase base = fields.getObject(i);
            if (!(base instanceof COSDictionary field)) continue;
            if (isSignatureField(field)) {
                fields.remove(i);
                actions.add("Removed digital signature field from " + location + "[" + i + "].");
                continue;
            }
            COSBase kids = field.getDictionaryObject(COSName.KIDS);
            if (kids instanceof COSArray childFields) {
                removeSignatureFields(childFields, actions, location + "[" + i + "]/Kids");
                if (childFields.size() == 0) field.removeItem(COSName.KIDS);
            }
        }
    }

    private static boolean isSignatureField(COSDictionary dict) {
        COSBase ft = dict.getDictionaryObject(COSName.getPDFName("FT"));
        return ft instanceof COSName n && "Sig".equalsIgnoreCase(n.getName());
    }

    private static boolean isSignatureFieldOrWidget(COSDictionary annotation) {
        if (isSignatureField(annotation)) return true;
        COSBase subtype = annotation.getDictionaryObject(COSName.SUBTYPE);
        if (!(subtype instanceof COSName n) || !"Widget".equalsIgnoreCase(n.getName())) return false;
        COSBase parent = annotation.getDictionaryObject(COSName.PARENT);
        return parent instanceof COSDictionary parentDict && isSignatureField(parentDict);
    }

    private void sanitizeDictionary(COSDictionary dict, String location,
                                    List<String> actions, Set<COSBase> visited) {
        if (dict == null || !visited.add(dict)) return;

        removeIfPresent(dict, COSName.JS, actions, "Removed JavaScript entry from " + location + ".");
        removeIfPresent(dict, COSName.getPDFName("JavaScript"), actions, "Removed JavaScript entry from " + location + ".");
        removeIfPresent(dict, COSName.getPDFName("AA"), actions, "Removed additional actions from " + location + ".");

        // File specifications: remove embedded-file and external-file references.
        COSBase type = dict.getDictionaryObject(COSName.TYPE);
        if (type instanceof COSName n && "Filespec".equalsIgnoreCase(n.getName())) {
            boolean changed = false;
            for (String key : List.of("EF", "F", "UF", "DOS", "Mac", "Unix")) {
                COSName name = COSName.getPDFName(key);
                if (dict.getDictionaryObject(name) != null) {
                    dict.removeItem(name);
                    changed = true;
                }
            }
            if (changed) actions.add("Removed PDF file-specification payload/reference from " + location + ".");
        }

        removeIfPresent(dict, COSName.getPDFName("AF"), actions,
                "Removed associated-file reference from " + location + ".");
        removeIfPresent(dict, COSName.getPDFName("XFA"), actions,
                "Removed XFA content from " + location + ".");

        // An EmbeddedFile stream may become unreachable after EF/FileSpec removal;
        // the reconstruction writer must never expose it through a surviving file spec.
        if (type instanceof COSName n && "EmbeddedFile".equalsIgnoreCase(n.getName())) {
            dict.removeItem(COSName.TYPE);
            actions.add("Disarmed embedded-file stream object at " + location + ".");
        }

        for (String key : List.of("RichMedia", "RichMediaContent", "RichMediaSettings", "3D", "3DA")) {
            removeIfPresent(dict, COSName.getPDFName(key), actions,
                    "Removed active /" + key + " content from " + location + ".");
        }

        COSBase ft = dict.getDictionaryObject(COSName.getPDFName("FT"));
        boolean signature =
                (ft instanceof COSName ftName && "Sig".equalsIgnoreCase(ftName.getName())) ||
                (type instanceof COSName typeName && "Sig".equalsIgnoreCase(typeName.getName()));
        if (signature) {
            removeIfPresent(dict, COSName.getPDFName("V"), actions,
                    "Removed digital signature value from " + location + ".");
            removeIfPresent(dict, COSName.getPDFName("ByteRange"), actions,
                    "Removed digital signature byte range from " + location + ".");
            removeIfPresent(dict, COSName.getPDFName("Contents"), actions,
                    "Removed digital signature contents from " + location + ".");
        }

        removeIfDangerousAction(dict, COSName.A, actions, location + "/A");
        removeIfDangerousAction(dict, COSName.OPEN_ACTION, actions, location + "/OpenAction");

        // /Next can be a single action dictionary or an array of actions. Filter
        // the array so a safe first action cannot lead into a dangerous chain.
        COSBase next = dict.getDictionaryObject(COSName.NEXT);
        if (next instanceof COSDictionary nextAction) {
            if (isDangerousAction(nextAction)) {
                dict.removeItem(COSName.NEXT);
                actions.add("Removed dangerous chained action from " + location + ".");
            } else {
                sanitizeDictionary(nextAction, location + "/Next", actions, visited);
            }
        } else if (next instanceof COSArray nextArray) {
            filterActionArray(nextArray, location + "/Next", actions, visited);
            if (nextArray.size() == 0) {
                dict.removeItem(COSName.NEXT);
                actions.add("Removed empty action chain from " + location + ".");
            }
        }

        // A URI action remains intact for approved schemes and is made inert for
        // dangerous schemes. The entire action is removed when its parent key is /A.
        COSBase actionType = dict.getDictionaryObject(COSName.S);
        if (actionType instanceof COSName s && "URI".equalsIgnoreCase(s.getName())) {
            String uri = stringValue(dict.getDictionaryObject(COSName.URI));
            if (PDFThreatAnalyzerBridge.isDangerousUri(uri)) {
                dict.removeItem(COSName.S);
                dict.removeItem(COSName.URI);
                actions.add("Disarmed dangerous URI action at " + location + ".");
            }
        }

        // Never retain a standalone embedded-file name tree.
        removeIfPresent(dict, COSName.getPDFName("EmbeddedFiles"), actions,
                "Removed embedded-file name tree from " + location + ".");

        for (var entry : new ArrayList<>(dict.entrySet())) {
            COSBase value = entry.getValue();
            if (value instanceof COSDictionary child) {
                sanitizeDictionary(child, location + "/" + entry.getKey().getName(), actions, visited);
            } else if (value instanceof COSArray array) {
                sanitizeArray(array, location + "/" + entry.getKey().getName(), actions, visited);
            }
        }
    }

    private void sanitizeArray(COSArray array, String location,
                               List<String> actions, Set<COSBase> visited) {
        if (array == null || !visited.add(array)) return;
        for (int i = array.size() - 1; i >= 0; i--) {
            COSBase value = array.getObject(i);
            if (value instanceof COSDictionary child) {
                sanitizeDictionary(child, location + "[" + i + "]", actions, visited);
            } else if (value instanceof COSArray childArray) {
                sanitizeArray(childArray, location + "[" + i + "]", actions, visited);
            }
        }
    }

    private void filterActionArray(COSArray array, String location,
                                   List<String> actions, Set<COSBase> visited) {
        for (int i = array.size() - 1; i >= 0; i--) {
            COSBase value = array.getObject(i);
            if (value instanceof COSDictionary action) {
                if (isDangerousAction(action)) {
                    array.remove(i);
                    actions.add("Removed dangerous chained action from " + location + "[" + i + "].");
                } else {
                    sanitizeDictionary(action, location + "[" + i + "]", actions, visited);
                }
            } else if (value instanceof COSArray nested) {
                filterActionArray(nested, location + "[" + i + "]", actions, visited);
                if (nested.size() == 0) array.remove(i);
            }
        }
    }

    private boolean removeIfDangerousAction(COSDictionary parent, COSName key,
                                            List<String> actions, String location) {
        COSBase value = parent.getDictionaryObject(key);
        if (value instanceof COSDictionary action && isDangerousAction(action)) {
            parent.removeItem(key);
            actions.add("Removed dangerous action at " + location + ".");
            return true;
        }
        return false;
    }

    private static void removeIfPresent(COSDictionary dict, COSName key,
                                        List<String> actions, String message) {
        if (dict.getDictionaryObject(key) != null) {
            dict.removeItem(key);
            actions.add(message);
        }
    }

    private boolean isDangerousAction(COSDictionary action) {
        if (action == null) return false;
        COSBase type = action.getDictionaryObject(COSName.S);
        if (!(type instanceof COSName name)) return false;
        String actionType = name.getName().toUpperCase(Locale.ROOT);
        if (BLOCKING_ACTIONS.contains(actionType)) return true;
        if ("URI".equals(actionType)) {
            return PDFThreatAnalyzerBridge.isDangerousUri(stringValue(action.getDictionaryObject(COSName.URI)));
        }
        return false;
    }

    private static String stringValue(COSBase base) {
        if (base instanceof COSString s) return s.getString();
        return base == null ? null : base.toString();
    }

    /** Package-private bridge keeps the URI policy in one implementation. */
    private static final class PDFThreatAnalyzerBridge {
        private static boolean isDangerousUri(String uri) {
            return threat.pdf.PDFSecurityPolicy.isDangerousUri(uri);
        }
    }
}
