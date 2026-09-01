package application;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.zip.ZipException;

/** Converts internal exceptions into concise operator-facing messages. */
public final class UserFacingError {
    private UserFacingError() { }

    public static String message(Throwable error, Path input, Path output) {
        Throwable root = rootCause(error);
        String text = root.getMessage() == null ? "" : root.getMessage().trim();

        if (root instanceof NoSuchFileException || contains(text, "does not exist")) {
            return "File doesn't exist: " + input;
        }
        if (root instanceof AccessDeniedException || containsAny(text, "access denied", "permission denied", "access is denied")) {
            return "Permission denied while accessing the file. Check the file permissions and try again.";
        }
        if (root instanceof ZipException || containsAny(text, "zip", "end header", "central directory", "not a zip")) {
            return "The file is damaged, incomplete, or is not a valid document package.";
        }
        if (containsAny(text, "unsafe ooxml zip entry path", "path traversal")) {
            return "The file contains an unsafe package path and cannot be processed safely.";
        }
        if (containsAny(text, "duplicate ooxml zip entry", "duplicate")) {
            return "The file contains duplicate package entries and cannot be processed safely.";
        }
        if (containsAny(text, "too many zip entries", "size limit", "exceeds the single-part size limit")) {
            return "The file is too large or contains too many internal entries to process safely.";
        }
        if (containsAny(text, "password", "encrypted", "encryption")) {
            return "The PDF is encrypted or password-protected and could not be safely opened without its password.";
        }
        if (containsAny(text, "parser", "parse", "malformed", "xml")) {
            return "The file could not be read because its document structure is invalid or malformed.";
        }
        if (containsAny(text, "output", "write", "create", "reconstruct")) {
            return "The sanitized output could not be created. Check the output path and permissions.";
        }
        return "The file could not be processed safely. Please check the file and try again.";
    }

    public static String outputMessage(Throwable error, Path output) {
        Throwable root = rootCause(error);
        String text = root.getMessage() == null ? "" : root.getMessage().trim();
        if (root instanceof AccessDeniedException || containsAny(text, "access denied", "permission denied")) {
            return "Output could not be written because permission was denied: " + output;
        }
        if (root instanceof FileSystemException || containsAny(text, "no such file", "not a directory")) {
            return "Output could not be created. Check that the output folder exists and is writable: " + output;
        }
        return "Output could not be created: " + output;
    }

    private static Throwable rootCause(Throwable error) {
        Throwable current = error;
        while (current != null && current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current == null ? new Exception() : current;
    }

    private static boolean contains(String value, String token) {
        return value.toLowerCase().contains(token.toLowerCase());
    }

    private static boolean containsAny(String value, String... tokens) {
        for (String token : tokens) {
            if (contains(value, token)) return true;
        }
        return false;
    }
}
