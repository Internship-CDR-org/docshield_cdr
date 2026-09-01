package security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

/** Safely stores files that cannot be trusted or processed. */
public final class QuarantineManager {
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS");

    private QuarantineManager() { }

    public static Path quarantine(Path input, String reason) throws IOException {
        if (input == null || !Files.isRegularFile(input)) {
            throw new IOException("Quarantine source file is unavailable.");
        }

        Path directory = Path.of("output", "quarantine").toAbsolutePath().normalize();
        Files.createDirectories(directory);

        String originalName = input.getFileName() == null ? "unknown-file" : input.getFileName().toString();
        String safeName = originalName.replaceAll("[^A-Za-z0-9._-]", "_");
        String prefix = FORMAT.format(LocalDateTime.now()) + "_" + safeName;
        Path destination = uniqueDestination(directory, prefix);
        Path temporary = Files.createTempFile(directory, ".docshield-quarantine-", ".tmp");

        try {
            Files.copy(input, temporary, StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING);
            moveIntoPlace(temporary, destination);
        } finally {
            Files.deleteIfExists(temporary);
        }

        String sha256 = sha256(destination);
        Path note = destination.resolveSibling(destination.getFileName() + ".txt");
        String report = "DocShield Quarantine Record\n" +
                "Original file: " + input.toAbsolutePath().normalize() + "\n" +
                "SHA-256: " + sha256 + "\n" +
                "Reason: " + sanitizeReason(reason) + "\n";
        Files.writeString(note, report);
        return destination;
    }

    private static Path uniqueDestination(Path directory, String prefix) throws IOException {
        Path candidate = directory.resolve(prefix + ".quarantined");
        int suffix = 1;
        while (Files.exists(candidate)) {
            candidate = directory.resolve(prefix + "_" + suffix++ + ".quarantined");
        }
        return candidate;
    }

    private static void moveIntoPlace(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
            Files.move(source, destination);
        }
    }

    private static String sha256(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 is unavailable in this Java runtime.", impossible);
        }
    }

    private static String sanitizeReason(String reason) {
        if (reason == null || reason.isBlank()) return "File could not be safely processed.";
        return reason.replaceAll("[\\r\\n]+", " ").trim();
    }
}
