package sanitization.common;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import org.junit.jupiter.api.Test;
import threat.common.SecurityFinding;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class RecursiveOOXMLSanitizerTest {

    @Test
    void cleanEmbeddedOOXMLIsPreservedAndReconstructed() throws Exception {
        OOXMLPackage outer = minimalPptxPackage();
        byte[] cleanNested = minimalDocxPackage(false);
        outer.addPart(new OOXMLPart(
                "ppt/embeddings/embeddedPackage1.bin",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                cleanNested));

        List<SecurityFinding> findings = new ArrayList<>();
        RecursiveOOXMLSanitizer.Result result =
                new RecursiveOOXMLSanitizer().sanitizeEmbeddedPackages(outer, findings);

        assertTrue(result.getActions().stream().anyMatch(a -> a.contains("Reconstructed and preserved")));
        assertTrue(outer.hasPart("ppt/embeddings/embeddedPackage1.bin"));
        byte[] rebuilt = outer.getPart("ppt/embeddings/embeddedPackage1.bin").getData();
        assertTrue(rebuilt.length > 0);
        assertEquals((byte) 'P', rebuilt[0]);
        assertEquals((byte) 'K', rebuilt[1]);
    }

    @Test
    void embeddedVbaIsSanitizedAndCleanNestedPackageIsPutBack() throws Exception {
        OOXMLPackage outer = minimalPptxPackage();
        byte[] nestedWithVba = minimalDocxPackage(true);
        outer.addPart(new OOXMLPart(
                "ppt/embeddings/embeddedPackage1.bin",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                nestedWithVba));

        List<SecurityFinding> findings = new ArrayList<>();
        RecursiveOOXMLSanitizer.Result result =
                new RecursiveOOXMLSanitizer().sanitizeEmbeddedPackages(outer, findings);

        assertTrue(outer.hasPart("ppt/embeddings/embeddedPackage1.bin"),
                "A sanitizable nested document should remain embedded");
        assertNotEquals(new String(nestedWithVba, StandardCharsets.ISO_8859_1),
                new String(outer.getPart("ppt/embeddings/embeddedPackage1.bin").getData(), StandardCharsets.ISO_8859_1));
        assertTrue(result.getActions().stream().anyMatch(a -> a.contains("Reconstructed and preserved")));
    }

    @Test
    void depthLimitIsFailClosedNotTrusted() throws Exception {
        OOXMLPackage outer = minimalPptxPackage();
        outer.addPart(new OOXMLPart(
                "ppt/embeddings/embeddedPackage1.bin",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                minimalDocxPackage(false)));

        List<SecurityFinding> findings = new ArrayList<>();
        RecursiveOOXMLSanitizer sanitizer = new RecursiveOOXMLSanitizer(0, 64 * 1024, 100, 10);
        sanitizer.sanitizeEmbeddedPackages(outer, findings);

        assertTrue(findings.stream().anyMatch(f -> f.getType().name().equals("SUSPICIOUS_ARCHIVE")));
        assertFalse(outer.hasPart("ppt/embeddings/embeddedPackage1.bin"),
                "Uninspectable content must fail closed rather than being trusted");
    }

    private OOXMLPackage minimalPptxPackage() {
        OOXMLPackage pkg = new OOXMLPackage();
        pkg.addPart(new OOXMLPart("[Content_Types].xml", "application/xml", "<Types/>".getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart("_rels/.rels", "application/vnd.openxmlformats-package.relationships+xml", "<Relationships/>".getBytes(StandardCharsets.UTF_8)));
        pkg.addPart(new OOXMLPart("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml", "<p:presentation xmlns:p=\"x\"/>".getBytes(StandardCharsets.UTF_8)));
        return pkg;
    }

    private byte[] minimalDocxPackage(boolean vba) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            put(zip, "[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".getBytes(StandardCharsets.UTF_8));
            put(zip, "_rels/.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>".getBytes(StandardCharsets.UTF_8));
            put(zip, "word/document.xml", "<w:document xmlns:w=\"x\"/>".getBytes(StandardCharsets.UTF_8));
            if (vba) put(zip, "word/vbaProject.bin", new byte[]{'M', 'Z', 0, 0});
        }
        return out.toByteArray();
    }

    private void put(ZipOutputStream zip, String name, byte[] data) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(data);
        zip.closeEntry();
    }
}
