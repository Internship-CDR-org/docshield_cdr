package identification;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class FileIdentifierComprehensiveTest {

    @TempDir
    Path tempDir;

    private final FileIdentifier identifier = new FileIdentifier();

    @Test
    void identifiesPdfCorrectly() throws Exception {
        Path pdf = tempDir.resolve("sample.pdf");
        Files.writeString(pdf, "%PDF-1.7\n%stream test\n%%EOF");

        FileInfo info = identifier.identify(pdf);
        assertEquals(Format.PDF, info.getFormat());
        assertTrue(info.isValid());
        assertTrue(info.isExtensionMatch());
        assertNotNull(info.getSha256());
    }

    @Test
    void identifiesRtfWithBomCorrectly() throws Exception {
        Path rtf = tempDir.resolve("document.rtf");
        byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] content = "{\\rtf1\\ansi\\deff0 {\\fonttbl{\\f0 Courier;}}\\f0\\fs20 Hello}".getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(bom);
        out.write(content);
        Files.write(rtf, out.toByteArray());

        FileInfo info = identifier.identify(rtf);
        assertEquals(Format.RTF, info.getFormat());
        assertTrue(info.isValid());
        assertTrue(info.isExtensionMatch());
    }

    @Test
    void detectsExtensionMismatchWhenPdfHasDocxExtension() throws Exception {
        Path mismatch = tempDir.resolve("spoofed.docx");
        Files.writeString(mismatch, "%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF");

        FileInfo info = identifier.identify(mismatch);
        assertEquals(Format.PDF, info.getFormat());
        assertFalse(info.isExtensionMatch());
        assertFalse(info.isValid());
    }

    @Test
    void detectsUnknownFormatForArbitraryZip() throws Exception {
        Path fakeDocx = tempDir.resolve("not-a-word-doc.docx");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(fakeDocx))) {
            zos.putNextEntry(new ZipEntry("unrelated.txt"));
            zos.write("hello".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        FileInfo info = identifier.identify(fakeDocx);
        assertEquals(Format.UNKNOWN, info.getFormat());
        assertFalse(info.isValid());
    }

    @Test
    void detectsDocxPackageStructure() throws Exception {
        Path docx = tempDir.resolve("valid.docx");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(docx))) {
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("word/document.xml"));
            zos.write("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        FileInfo info = identifier.identify(docx);
        assertEquals(Format.DOCX, info.getFormat());
        assertTrue(info.isValid());
        assertTrue(info.isExtensionMatch());
    }

    @Test
    void detectsPptxPackageStructure() throws Exception {
        Path pptx = tempDir.resolve("presentation.pptx");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(pptx))) {
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("ppt/presentation.xml"));
            zos.write("<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        FileInfo info = identifier.identify(pptx);
        assertEquals(Format.PPTX, info.getFormat());
        assertTrue(info.isValid());
        assertTrue(info.isExtensionMatch());
    }

    @Test
    void detectsXlsxPackageStructure() throws Exception {
        Path xlsx = tempDir.resolve("sheet.xlsx");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(xlsx))) {
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("xl/workbook.xml"));
            zos.write("<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        FileInfo info = identifier.identify(xlsx);
        assertEquals(Format.XLSX, info.getFormat());
        assertTrue(info.isValid());
        assertTrue(info.isExtensionMatch());
    }

    @Test
    void throwsOnNonExistentFile() {
        Path missing = tempDir.resolve("does-not-exist.pdf");
        assertThrows(IOException.class, () -> identifier.identify(missing));
    }
}
