package validation.ooxml;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import model.ooxml.OOXMLRelationship;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Structural validator for reconstructed OPC/OOXML packages. */
public class OOXMLIntegrityValidator {

    public boolean validate(OOXMLPackage packageData) {
        if (packageData == null || !packageData.hasPart("[Content_Types].xml") ||
                packageData.getContentTypes().isEmpty()) return false;

        Set<String> names = new HashSet<>();
        for (OOXMLPart part : packageData.getParts()) {
            if (part == null || part.getPartName() == null || part.getPartName().isBlank()) return false;
            String name = normalizePartName(part.getPartName());
            if (name == null || name.isBlank() || containsTraversal(name) || !names.add(name)) return false;
            if (!"[content_types].xml".equals(name.toLowerCase(Locale.ROOT)) &&
                    resolveContentType(packageData, name) == null) return false;
        }

        // Every explicit Override must point at a physical part.
        for (String key : packageData.getContentTypes().keySet()) {
            if (key == null || key.isBlank()) return false;
            if (!key.startsWith(".") && !packageData.hasPart(key)) return false;
        }

        Set<String> relationshipKeys = new HashSet<>();
        for (OOXMLRelationship relationship : packageData.getRelationships()) {
            if (relationship == null || isBlank(relationship.getId()) ||
                    isBlank(relationship.getType()) || isBlank(relationship.getTarget())) return false;

            String source = normalizePartName(relationship.getSourcePart());
            String key = (source == null ? "" : source) + "\n" + relationship.getId();
            if (!relationshipKeys.add(key)) return false;

            if (source != null && !source.isBlank() && !packageData.hasPart(source)) return false;
            if (relationship.isExternal()) continue;

            String target = resolveTarget(source, relationship.getTarget());
            if (target == null || target.isBlank() || containsTraversal(target) || !packageData.hasPart(target)) return false;
        }

        return true;
    }

    public boolean validate(OOXMLPackage originalPackage, OOXMLPackage reconstructedPackage) {
        if (originalPackage == null || reconstructedPackage == null || !validate(reconstructedPackage)) return false;
        for (OOXMLPart part : reconstructedPackage.getParts()) {
            if (part == null || part.getPartName() == null || !originalPackage.hasPart(part.getPartName())) return false;
        }
        return true;
    }

    private String resolveContentType(OOXMLPackage pkg, String partName) {
        String exact = pkg.getContentType(partName);
        if (exact != null && !exact.isBlank()) return exact;
        int dot = partName.lastIndexOf('.');
        if (dot >= 0 && dot < partName.length() - 1) {
            String byExtension = pkg.getContentType("." + partName.substring(dot + 1).toLowerCase(Locale.ROOT));
            if (byExtension != null && !byExtension.isBlank()) return byExtension;
        }
        return null;
    }

    private String resolveTarget(String source, String target) {
        String t = target == null ? null : target.trim().replace('\\', '/');
        if (t == null || t.isBlank()) return null;
        if (t.startsWith("/")) return normalizePath(t);
        if (source == null || source.isBlank()) return normalizePath(t);
        int slash = source.lastIndexOf('/');
        String dir = slash < 0 ? "" : source.substring(0, slash);
        return normalizePath(dir.isEmpty() ? t : dir + "/" + t);
    }

    private String normalizePartName(String value) {
        if (value == null) return null;
        return value.trim().replace('\\', '/').replaceFirst("^/+", "");
    }

    private String normalizePath(String path) {
        if (path == null) return null;
        String[] pieces = path.replace('\\', '/').split("/");
        List<String> result = new java.util.ArrayList<>();
        for (String piece : pieces) {
            if (piece.isEmpty() || ".".equals(piece)) continue;
            if ("..".equals(piece)) {
                if (result.isEmpty()) return null;
                result.remove(result.size() - 1);
            } else result.add(piece);
        }
        return String.join("/", result);
    }

    private boolean containsTraversal(String value) {
        if (value == null || value.startsWith("/")) return true;
        for (String p : value.replace('\\', '/').split("/")) if ("..".equals(p)) return true;
        return false;
    }

    private boolean isBlank(String value) { return value == null || value.isBlank(); }
}
