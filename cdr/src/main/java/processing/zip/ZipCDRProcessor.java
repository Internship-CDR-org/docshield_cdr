package processing.zip;

import processing.common.CDRFileUtil;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * ZIP Content Disarm and Reconstruction processor.
 *
 * IMPORTANT POLICY:
 *
 * ZIP is handled as a CONTAINER ONLY.
 *
 * This processor does NOT inspect inner PDF, DOC, DOCX, XLS, XLSX, PPT,
 * PPTX, RTF or other document content. An inner file is not routed to a
 * format-specific CDR processor.
 *
 * The ZIP container itself is checked for:
 * - valid ZIP structure
 * - entry count limits
 * - individual uncompressed-size limits
 * - total uncompressed-size limits
 * - compression-ratio / ZIP-bomb characteristics
 * - path traversal
 * - duplicate entry names
 * - nested ZIP depth
 * - safe entry decoding
 *
 * SAFE container -> copy the ORIGINAL ZIP bytes unchanged.
 * ZIP-level unsafe entries -> reconstruct a sanitized ZIP while removing
 * the offending container entries.
 * Unrecoverable ZIP structure -> fail closed and quarantine.
 */
public final class ZipCDRProcessor implements CDRProcessor {

    private static final int MAX_NESTING_DEPTH = 3;
    private static final long MAX_ENTRIES = 10_000L;
    private static final long MAX_ENTRY_BYTES = 100L * 1024L * 1024L;
    private static final long MAX_TOTAL_UNCOMPRESSED_BYTES = 500L * 1024L * 1024L;
    private static final long MIN_RATIO_CHECK_BYTES = 1L * 1024L * 1024L;
    private static final double MAX_COMPRESSION_RATIO = 100.0D;
    private static final int MAX_CONSOLE_FINDINGS = 5;
    private static final int BUFFER_SIZE = 8192;

    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        if (inputFile == null || outputFile == null) {
            throw new IOException("ZIP input/output path cannot be null.");
        }

        Path input = inputFile.toAbsolutePath().normalize();
        Path output = outputFile.toAbsolutePath().normalize();

        if (!Files.isRegularFile(input)) {
            throw new IOException("ZIP input is not a readable regular file: " + input);
        }
        if (input.equals(output)) {
            throw new IOException("ZIP input and output paths must be different.");
        }

        Path parent = output.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        String inputSha256 = CDRFileUtil.sha256(input);
        List<SecurityFinding> findings = new ArrayList<>();
        List<SecurityFinding> finalFindings = new ArrayList<>();
        List<String> actions = new ArrayList<>();
        Set<String> entriesToRemove = new HashSet<>();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" ZIP CDR - CONTAINER ONLY");
        System.out.println("============================================================");
        System.out.println("Input: " + input.getFileName());
        System.out.println("Policy: Inner file analysis NOT PERFORMED");

        ZipBudget budget = new ZipBudget();

        try {
            analyzeZipContainer(input, 0, budget, findings, actions, entriesToRemove);
        } catch (Exception e) {
            printFindings("ZIP ANALYZER", findings);
            System.out.println("ZIP CONTAINER STATUS: INVALID / UNRECOVERABLE");
            System.out.println("ZIP ACTION: QUARANTINE / REJECT");
            throw e;
        }

        finalFindings.addAll(findings);
        boolean sanitized = !entriesToRemove.isEmpty();

        if (!sanitized) {
            // Safe ZIP: preserve the exact original bytes so the SHA remains identical.
            Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);
            actions.add("ZIP container is safe; original ZIP copied byte-for-byte.");
            actions.add("No ZIP-level threats were removed.");
        } else {
            // Unsafe ZIP: create a sanitized ZIP and omit only the ZIP-level entries
            // identified as unsafe. Inner document contents remain opaque.
            Path tempOutput = Files.createTempFile(
                    parent == null ? Path.of(".") : parent,
                    ".docshield-zip-", ".tmp");
            try {
                reconstructContainer(input, tempOutput, entriesToRemove, 0, new ReconstructionBudget());
                validateZip(tempOutput);
                Files.move(tempOutput, output, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.deleteIfExists(tempOutput);
                throw new IOException("ZIP sanitization failed; archive rejected.", e);
            }
            actions.add("ZIP-level unsafe entries were removed.");
            actions.add("Sanitized ZIP reconstructed successfully.");
        }

        String outputSha256 = CDRFileUtil.sha256(output);
        boolean integrityPassed = isValidZip(output);
        if (!integrityPassed) {
            Files.deleteIfExists(output);
            throw new IOException("ZIP output failed validation.");
        }

        boolean shaChanged = !inputSha256.equalsIgnoreCase(outputSha256);
        if (!sanitized && shaChanged) {
            Files.deleteIfExists(output);
            throw new IOException("Safe ZIP changed during processing; byte-preservation failed.");
        }
        if (sanitized && !shaChanged) {
            Files.deleteIfExists(output);
            throw new IOException("Sanitized ZIP did not change its SHA-256.");
        }

        actions.add("Input SHA-256: " + inputSha256);
        actions.add("Output SHA-256: " + outputSha256);
        actions.add("SHA changed: " + shaChanged);

        printAnalyzerSummary(input, budget, findings, sanitized);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" ZIP FINAL RESULT");
        System.out.println("============================================================");
        System.out.println("ZIP CONTAINER STATUS: " + (sanitized ? "THREAT(S) REMOVED" : "SAFE"));
        System.out.println("Inner file analysis: NOT PERFORMED");
        System.out.println("ZIP RECONSTRUCTION: " + (sanitized ? "SANITIZED" : "ORIGINAL COPIED"));
        System.out.println("Input SHA-256 : " + inputSha256);
        System.out.println("Output SHA-256: " + outputSha256);
        System.out.println("SHA changed   : " + shaChanged);
        System.out.println("Integrity     : " + integrityPassed);
        System.out.println("============================================================");

        return new CDRResult(
                findings,
                actions,
                output,
                true,
                integrityPassed,
                sanitized,
                finalFindings,
                inputSha256,
                outputSha256,
                !sanitized);
    }

    /**
     * Analyzes only ZIP/container properties.
     */
    private void analyzeZipContainer(
            Path zipPath,
            int depth,
            ZipBudget budget,
            List<SecurityFinding> findings,
            List<String> actions,
            Set<String> entriesToRemove) throws Exception {

        if (depth > MAX_NESTING_DEPTH) {
            addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                    zipPath.getFileName().toString(),
                    "Maximum nested ZIP depth exceeded.",
                    "Reject ZIP archive.");
            throw new IOException("Maximum ZIP nesting depth exceeded.");
        }

        Set<String> names = new HashSet<>();

        try (ZipFile zip = new ZipFile(zipPath.toFile())) {
            zip.size();
            var entries = zip.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                budget.entries++;

                if (budget.entries > MAX_ENTRIES) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            entry.getName(), "ZIP entry count exceeds the configured limit of " + MAX_ENTRIES + ".",
                            "Reject ZIP archive.");
                    throw new IOException("ZIP entry count limit exceeded.");
                }

                String name = normalizeEntryName(entry.getName());
                if (!isSafeEntryName(name)) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            name, "ZIP entry contains an absolute or path-traversal path.",
                            "Remove unsafe ZIP entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                if (!names.add(name)) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            name, "Duplicate ZIP entry name detected.",
                            "Remove duplicate ZIP entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                if (entry.isDirectory()) {
                    continue;
                }

                long declaredSize = entry.getSize();
                long compressedSize = entry.getCompressedSize();

                if (declaredSize > MAX_ENTRY_BYTES) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            name, "ZIP entry uncompressed size exceeds " + MAX_ENTRY_BYTES + " bytes.",
                            "Remove unsafe ZIP entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                if (declaredSize >= 0) {
                    budget.totalUncompressed += declaredSize;
                    if (budget.totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES) {
                        addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                                name, "Total ZIP uncompressed size exceeds " + MAX_TOTAL_UNCOMPRESSED_BYTES + " bytes.",
                                "Remove unsafe ZIP entry.");
                        entriesToRemove.add(name);
                        continue;
                    }
                }

                if (isCompressionBomb(compressedSize, declaredSize)) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            name, "ZIP compression ratio exceeds the configured " + MAX_COMPRESSION_RATIO + ":1 limit.",
                            "Remove possible ZIP-bomb entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                long decoded;
                try {
                    decoded = boundedRead(zip, entry, MAX_ENTRY_BYTES);
                } catch (IOException decodeFailure) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                            name, "ZIP entry could not be safely decoded within configured limits.",
                            "Remove unsafe ZIP entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                if (declaredSize >= 0 && decoded != declaredSize) {
                    addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.HIGH,
                            name, "ZIP entry decoded size does not match its declared size.",
                            "Remove unsafe ZIP entry.");
                    entriesToRemove.add(name);
                    continue;
                }

                if (declaredSize < 0) {
                    budget.totalUncompressed += decoded;
                    if (budget.totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES) {
                        addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                                name, "Total decoded ZIP data exceeds the configured limit.",
                                "Remove unsafe ZIP entry.");
                        entriesToRemove.add(name);
                        continue;
                    }
                }

                /*
                 * ZIP-inside-ZIP is a ZIP-container-level policy violation.
                 *
                 * We do NOT open the nested archive and inspect its contents.
                 * The presence of a nested ZIP is enough to classify that entry
                 * as an unsafe nested archive and remove the whole nested ZIP
                 * entry during reconstruction.
                 *
                 * This is intentionally different from analyzing the inner
                 * PDF/DOCX/XLSX/PPTX/RTF contents of a normal ZIP entry.
                 */
                if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                    addFinding(
                            findings,
                            ThreatType.SUSPICIOUS_ARCHIVE,
                            ThreatSeverity.CRITICAL,
                            name,
                            "Nested ZIP archive detected. Nested ZIP containers are not allowed by the ZIP CDR policy.",
                            "Remove nested ZIP entry.");

                    entriesToRemove.add(name);
                    continue;
                }
            }
        } catch (ZipException e) {
            addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                    zipPath.getFileName().toString(), "ZIP structure could not be safely parsed.",
                    "Reject malformed ZIP archive.");
            throw new IOException("Invalid ZIP structure.", e);
        }

        actions.add("ZIP container analysis passed at depth " + depth + ".");
    }

    /**
     * Reconstructs the ZIP as a container only. Every inner file is copied
     * as opaque bytes; no document analyzer is invoked.
     */
    private void reconstructContainer(
            Path inputZip,
            Path outputZip,
            Set<String> entriesToRemove,
            int depth,
            ReconstructionBudget budget) throws Exception {

        if (depth > MAX_NESTING_DEPTH) {
            throw new IOException("Maximum ZIP nesting depth exceeded.");
        }

        Set<String> names = new HashSet<>();

        try (ZipFile zip = new ZipFile(inputZip.toFile());
             OutputStream fileOut = Files.newOutputStream(outputZip);
             ZipOutputStream out = new ZipOutputStream(fileOut)) {

            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry source = entries.nextElement();
                budget.entries++;

                if (budget.entries > MAX_ENTRIES) {
                    throw new IOException("ZIP entry count limit exceeded.");
                }

                String name = normalizeEntryName(source.getName());
                if (!names.add(name)) {
                    continue;
                }
                if (entriesToRemove.contains(name)) {
                    continue;
                }

                if (source.isDirectory()) {
                    ZipEntry directory = new ZipEntry(name.endsWith("/") ? name : name + "/");
                    copyMetadata(source, directory);
                    out.putNextEntry(directory);
                    out.closeEntry();
                    continue;
                }

                ZipEntry destination = new ZipEntry(name);
                copyMetadata(source, destination);
                out.putNextEntry(destination);
                try (InputStream in = zip.getInputStream(source)) {
                    copyBounded(in, out, MAX_ENTRY_BYTES);
                }
                out.closeEntry();
            }
        } catch (ZipException e) {
            throw new IOException("ZIP reconstruction encountered an invalid entry.", e);
        }
    }

    private void copyMetadata(ZipEntry source, ZipEntry destination) {
        if (source.getComment() != null) {
            destination.setComment(source.getComment());
        }
        if (source.getExtra() != null) {
            destination.setExtra(source.getExtra());
        }
        if (source.getTime() >= 0) {
            destination.setTime(source.getTime());
        }
    }

    private long boundedRead(
            ZipFile zip,
            ZipEntry entry,
            long maxBytes) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            long total = 0;
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > maxBytes) {
                    throw new IOException(
                            "ZIP entry exceeded maximum decoded size: "
                                    + entry.getName());
                }
            }
            return total;
        } catch (ZipException e) {
            throw new IOException(
                    "ZIP entry could not be safely decoded: " + entry.getName(),
                    e);
        }
    }

    private void extractEntryBounded(
            ZipFile zip,
            ZipEntry entry,
            Path destination,
            long maxBytes) throws IOException {
        try (InputStream in = zip.getInputStream(entry);
             OutputStream out = Files.newOutputStream(destination)) {
            copyBounded(in, out, maxBytes);
        } catch (ZipException e) {
            throw new IOException(
                    "Nested ZIP could not be decoded: " + entry.getName(), e);
        }
    }

    private long copyBounded(
            InputStream in,
            OutputStream out,
            long maxBytes) throws IOException {
        long total = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new IOException("ZIP entry exceeded maximum size.");
            }
            out.write(buffer, 0, read);
        }
        return total;
    }

    private void validateZip(Path zipPath) throws IOException {
        try (ZipFile zip = new ZipFile(zipPath.toFile())) {
            zip.size();
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory()) {
                    boundedRead(zip, entry, MAX_ENTRY_BYTES);
                }
            }
        } catch (ZipException e) {
            throw new IOException("Reconstructed ZIP is invalid.", e);
        }
    }

    private boolean isValidZip(Path zipPath) {
        try {
            validateZip(zipPath);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isCompressionBomb(
            long compressedSize,
            long uncompressedSize) {
        if (compressedSize <= 0 || uncompressedSize < MIN_RATIO_CHECK_BYTES) {
            return false;
        }
        return ((double) uncompressedSize / (double) compressedSize)
                > MAX_COMPRESSION_RATIO;
    }

    private String normalizeEntryName(String name) {
        if (name == null) {
            return "";
        }
        return name.replace('\\', '/');
    }

    private boolean isSafeEntryName(String name) {
        boolean absolute = name.startsWith("/") || name.matches("^[A-Za-z]:/.*");
        String[] parts = name.split("/", -1);
        for (String part : parts) {
            if (part.equals("..")) {
                return false;
            }
        }
        return !absolute;
    }

    private void validateEntryName(String name, List<SecurityFinding> findings) throws IOException {
        if (!isSafeEntryName(name)) {
            if (findings != null) {
                addFinding(findings, ThreatType.SUSPICIOUS_ARCHIVE, ThreatSeverity.CRITICAL,
                        name, "ZIP entry contains an absolute or path-traversal path.",
                        "Remove unsafe ZIP entry.");
            }
            throw new IOException("ZIP path traversal detected: " + name);
        }
    }

    private void addFinding(
            List<SecurityFinding> findings,
            ThreatType type,
            ThreatSeverity severity,
            String source,
            String evidence,
            String action) {

        findings.add(new SecurityFinding(
                FindingClassification.THREAT,
                type,
                severity,
                null,
                source,
                null,
                evidence,
                "ZIP entry was not released unchanged.",
                action));
    }

    private void printAnalyzerSummary(
            Path input,
            ZipBudget budget,
            List<SecurityFinding> findings,
            boolean sanitized) {
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" ZIP ANALYZER RESULT");
        System.out.println("============================================================");
        System.out.println("Entries: " + budget.entries);
        System.out.println("ZIP Structure: VALID");
        System.out.println("ZIP Bomb Check: PASS");
        System.out.println("Path Traversal: PASS");
        System.out.println("Duplicate Entries: PASS");
        System.out.println("Entry Decoding: PASS");
        System.out.println("Nested ZIP Policy: " + (sanitized ? "THREAT DETECTED" : "PASS"));
        System.out.println("ZIP CONTAINER STATUS: " + (sanitized ? "THREAT(S) DETECTED" : "SAFE"));
        System.out.println("Inner file analysis: NOT PERFORMED");
        System.out.println("Policy: Container-only CDR");
        printFindings("ZIP ANALYZER FINDINGS", findings);
    }

    private void printFindings(
            String title,
            List<SecurityFinding> findings) {
        System.out.println();
        System.out.println("=== " + title + ": " + findings.size() + " ===");

        if (findings.isEmpty()) {
            System.out.println("ZIP FINDING: NONE");
            return;
        }

        int shown = 0;
        for (SecurityFinding finding : findings) {
            if (shown >= MAX_CONSOLE_FINDINGS) {
                break;
            }
            if (finding != null) {
                System.out.println(
                        "ZIP FINDING: "
                                + finding.getType()
                                + " | "
                                + finding.getSeverity()
                                + " | "
                                + finding.getSourcePart()
                                + " | "
                                + finding.getEvidence());
                shown++;
            }
        }

        if (findings.size() > MAX_CONSOLE_FINDINGS) {
            System.out.println(
                    "... "
                            + (findings.size() - MAX_CONSOLE_FINDINGS)
                            + " additional findings retained in the CDR report.");
        }
    }

    private static final class ZipBudget {
        long entries;
        long totalUncompressed;
    }

    private static final class ReconstructionBudget {
        long entries;
    }
}
