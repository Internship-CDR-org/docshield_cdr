package security.sandbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Enforces strict filesystem jail boundaries to protect against:
 * - Zip Slip / archive path traversal attacks
 * - Directory breakout via symlinks or ".." path segments
 * - Arbitrary file overwrite / read outside designated sandbox directories
 */
public final class PathSandbox {

    private PathSandbox() { }

    /**
     * Resolves a relative path against an authorized root jail and verifies that
     * the resulting path remains strictly inside that jail.
     *
     * @param rootJail Authorized root directory
     * @param relativePath Relative subpath to resolve
     * @return Canonicalized safe Path inside rootJail
     * @throws SecurityException if the path attempts to escape the root jail
     */
    public static Path resolveSafe(Path rootJail, String relativePath) {
        Objects.requireNonNull(rootJail, "Root jail path cannot be null");
        Objects.requireNonNull(relativePath, "Relative path cannot be null");

        assertSafeRelativePath(relativePath);

        Path normalizedRoot = rootJail.toAbsolutePath().normalize();
        Path candidate = normalizedRoot.resolve(relativePath).normalize();

        if (!candidate.startsWith(normalizedRoot)) {
            throw new SecurityException("Path traversal violation: '" + relativePath +
                    "' escapes sandbox root '" + normalizedRoot + "'");
        }

        return candidate;
    }

    /**
     * Validates that an existing path is strictly inside an authorized jail boundary.
     *
     * @param rootJail Authorized root directory
     * @param target Existing or proposed path
     * @throws SecurityException if target escapes rootJail
     */
    public static void validateWithin(Path rootJail, Path target) {
        Objects.requireNonNull(rootJail, "Root jail path cannot be null");
        Objects.requireNonNull(target, "Target path cannot be null");

        Path normalizedRoot = rootJail.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();

        if (!normalizedTarget.startsWith(normalizedRoot)) {
            throw new SecurityException("Security violation: path '" + normalizedTarget +
                    "' is outside authorized sandbox boundary '" + normalizedRoot + "'");
        }
    }

    /**
     * Inspects a ZIP archive entry name for directory traversal (Zip Slip),
     * null bytes, leading slashes, and Windows drive/stream specifiers.
     *
     * @param entryName The raw ZIP entry name
     * @throws IOException if the entry name represents a security risk
     */
    public static void assertSafeZipEntry(String entryName) throws IOException {
        if (entryName == null || entryName.isBlank()) {
            throw new IOException("ZIP entry name cannot be null or empty.");
        }

        if (entryName.indexOf('\0') >= 0) {
            throw new IOException("Null byte detected in ZIP entry: " + entryName);
        }

        // Check for directory traversal sequences
        if (entryName.contains("../") || entryName.contains("..\\") ||
                entryName.equals("..") || entryName.endsWith("/..") || entryName.endsWith("\\..")) {
            throw new IOException("Zip Slip directory traversal attempt detected in entry: " + entryName);
        }

        // Check for absolute or drive-letter paths
        if (entryName.startsWith("/") || entryName.startsWith("\\") ||
                (entryName.length() >= 2 && entryName.charAt(1) == ':')) {
            throw new IOException("Absolute path detected in ZIP entry: " + entryName);
        }

        // Check for alternate data streams (Windows ::$DATA or file:stream)
        if (entryName.contains(":") && !entryName.startsWith("http")) {
            throw new IOException("Invalid stream or colon sequence in ZIP entry: " + entryName);
        }
    }

    private static void assertSafeRelativePath(String path) {
        if (path.indexOf('\0') >= 0) {
            throw new SecurityException("Null byte in path: " + path);
        }
        if (path.startsWith("/") || path.startsWith("\\") ||
                (path.length() >= 2 && path.charAt(1) == ':')) {
            throw new SecurityException("Path must be relative, got: " + path);
        }
        if (path.contains("../") || path.contains("..\\") || path.equals("..")) {
            throw new SecurityException("Path traversal sequence '..' detected: " + path);
        }
    }
}
