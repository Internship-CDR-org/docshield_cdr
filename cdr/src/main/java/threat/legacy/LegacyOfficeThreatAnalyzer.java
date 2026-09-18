package threat.legacy;

import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.poifs.filesystem.NotOLE2FileException;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Non-executing structural/content inspection for legacy Office binary files. */
public final class LegacyOfficeThreatAnalyzer {
    private static final java.util.regex.Pattern XLS_DDE_FORMULA = java.util.regex.Pattern.compile(
            "(?is)(?:^|[\"'])(?:cmd(?:\\.exe)?|powershell(?:\\.exe)?|pwsh(?:\\.exe)?|wscript(?:\\.exe)?|cscript(?:\\.exe)?|mshta(?:\\.exe)?|rundll32(?:\\.exe)?)[^!\\r\\n]{0,8192}\\![A-Za-z]{1,3}\\$?\\d+"
    );


    public List<SecurityFinding> analyze(Path file, String format) throws IOException {
        if (file == null || !Files.isRegularFile(file) || !Files.isReadable(file))
            throw new IOException(format + " security inspection requires a readable regular file.");

        byte[] data = Files.readAllBytes(file);
        String normalizedFormat = format == null ? "" : format.toUpperCase(Locale.ROOT);
        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        List<SecurityFinding> findings = new ArrayList<>();

        inspectOleStorage(file, normalizedFormat, findings);

        if (normalizedFormat.equals("XLS")) {
            inspectXlsFormulas(file, findings);
        }

        if (normalizedFormat.equals("PPT") && containsRecordType(data, 0x0FF3)) {
            add(findings, ThreatType.DANGEROUS_ACTION, ThreatSeverity.CRITICAL,
                    "Legacy PPT InteractiveInfoAtom record detected.",
                    "The binary presentation contains an interactive action capable of invoking active content or a macro/OLE target.",
                    "Remove the dangerous action during isolated PPT → PPTX CDR conversion.");
        }

        if (containsAny(text, "powershell.exe", "-encodedcommand", "invoke-expression", "wscript.shell")) {
            ThreatType type = normalizedFormat.equals("PPT") && containsRecordType(data, 0x0FF3)
                    ? ThreatType.DANGEROUS_ACTION : ThreatType.EXECUTABLE_PAYLOAD;
            if (!hasType(findings, type)) {
                add(findings, type, ThreatSeverity.CRITICAL,
                        "Legacy " + normalizedFormat + " contains a command/script execution indicator.",
                        "The binary Office file contains a command or scripting construct capable of launching external code.",
                        "Remove the active content during isolated legacy-to-OOXML CDR conversion.");
            }
        }

        if (normalizedFormat.equals("XLS") && XLS_DDE_FORMULA.matcher(text).find()) {
            add(findings, ThreatType.DDE, ThreatSeverity.CRITICAL,
                    "Legacy XLS command-pipe DDE indicator detected.",
                    "Dynamic Data Exchange can invoke external applications or retrieve external data.",
                    "Remove the DDE construct during legacy XLS → XLSX CDR conversion.");
        }
        return findings;
    }

    private void inspectOleStorage(Path file, String format, List<SecurityFinding> findings) throws IOException {
        byte[] header = new byte[8];
        try (var in = Files.newInputStream(file)) {
            int read = in.read(header);
            if (read < 8 || !hasOleSignature(header)) return;
        }
        try (POIFSFileSystem fs = new POIFSFileSystem(file.toFile())) {
            scanDirectory(fs.getRoot(), "", findings, format);
        } catch (IOException e) {
            throw new IOException("Legacy " + format + " security inspection failed: " + e.getMessage(), e);
        }
    }

    private void scanDirectory(DirectoryNode directory, String parent, List<SecurityFinding> findings, String format) throws IOException {
        for (Entry entry : directory) {
            if (entry == null) continue;
            String name = entry.getName();
            String current = parent.isEmpty() ? name : parent + "/" + name;
            String lower = name.toLowerCase(Locale.ROOT);
            if (entry instanceof DirectoryNode child) {
                if (isVbaName(lower)) {
                    addVba(findings, format, current, "Legacy " + format + " VBA project storage detected at " + current);
                }
                scanDirectory(child, current, findings, format);
            } else if (isVbaName(lower) || isVbaStream(lower, parent)) {
                addVba(findings, format, current, "Legacy " + format + " VBA project stream detected at " + current);
            }
        }
    }

    private void inspectXlsFormulas(Path file, List<SecurityFinding> findings) throws IOException {
        try (var input = Files.newInputStream(file); HSSFWorkbook workbook = new HSSFWorkbook(input)) {
            for (int s = 0; s < workbook.getNumberOfSheets(); s++) {
                HSSFSheet sheet = workbook.getSheetAt(s);
                for (Row row : sheet) {
                    for (Cell cell : row) {
                        if (cell != null && cell.getCellType() == org.apache.poi.ss.usermodel.CellType.FORMULA) {
                            String formula = cell.getCellFormula();
                            if (formula != null && (formula.toUpperCase(Locale.ROOT).contains("DDE")
                                    || XLS_DDE_FORMULA.matcher(formula).find())) {
                                add(findings, ThreatType.DDE, ThreatSeverity.CRITICAL,
                                        "Legacy XLS DDE formula detected at " + sheet.getSheetName() + "!" + cell.getAddress() + ": " + formula,
                                        "Dynamic Data Exchange can invoke external applications or retrieve external data.",
                                        "Remove the DDE construct during legacy XLS → XLSX CDR conversion.");
                                return;
                            }
                        }
                    }
                }
            }
        } catch (NotOLE2FileException e) {
            // The raw-byte inspection performed by analyze() remains authoritative
            // for non-OLE or synthetic inputs. There is no structured XLS formula
            // model to inspect when the input is not an OLE2 workbook.
        } catch (RuntimeException e) {
            throw new IOException("Legacy XLS formula security inspection failed: " + e.getMessage(), e);
        }
    }

    private boolean isVbaName(String name) {
        return "vba".equals(name) || "macros".equals(name) || name.contains("_vba_project");
    }
    private boolean isVbaStream(String name, String parent) {
        String p = parent == null ? "" : parent.toLowerCase(Locale.ROOT);
        return (name.equals("dir") || name.equals("project") || name.equals("projectwm")) &&
                (p.contains("vba") || p.contains("macro"));
    }
    private boolean hasOleSignature(byte[] data) {
        return data != null && data.length >= 8 && (data[0]&0xFF)==0xD0 && (data[1]&0xFF)==0xCF &&
                (data[2]&0xFF)==0x11 && (data[3]&0xFF)==0xE0 && (data[4]&0xFF)==0xA1 &&
                (data[5]&0xFF)==0xB1 && (data[6]&0xFF)==0x1A && (data[7]&0xFF)==0xE1;
    }
    private boolean containsAny(String text, String... tokens) { for (String t : tokens) if (text.contains(t)) return true; return false; }
    private boolean hasType(List<SecurityFinding> findings, ThreatType type) { for (SecurityFinding f : findings) if (f != null && f.getType() == type) return true; return false; }
    private boolean containsRecordType(byte[] data, int recordType) {
        if (data == null || data.length < 8) return false;
        int lo = recordType & 0xFF, hi = (recordType >>> 8) & 0xFF;
        for (int i=0; i+8<=data.length; i++) {
            if ((data[i+2]&0xFF)==lo && (data[i+3]&0xFF)==hi) {
                long length = (data[i+4]&0xFFL) | ((data[i+5]&0xFFL)<<8) | ((data[i+6]&0xFFL)<<16) | ((data[i+7]&0xFFL)<<24);
                if (length <= data.length - (i+8L)) return true;
            }
        }
        return false;
    }
    private void addVba(List<SecurityFinding> findings, String format, String location, String evidence) {
        if (hasType(findings, ThreatType.VBA_PROJECT)) return;
        add(findings, ThreatType.VBA_PROJECT, ThreatSeverity.HIGH, evidence,
                "The legacy binary " + format + " contains a VBA macro project.",
                "Remove the macro-bearing content during isolated " + format + " → OOXML CDR conversion.");
    }
    private static void add(List<SecurityFinding> out, ThreatType type, ThreatSeverity severity,
                            String evidence, String description, String action) {
        out.add(new SecurityFinding(FindingClassification.THREAT, type, severity, null, null, null,
                evidence, description, action));
    }
}
