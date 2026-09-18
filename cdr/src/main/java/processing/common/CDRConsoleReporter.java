package processing.common;

import threat.common.SecurityFinding;

import java.util.List;

/**
 * Consistent console representation for every CDR format.
 *
 * <p>The analyzer list represents findings before sanitization. The final list
 * represents findings remaining after reconstruction and post-CDR re-analysis.</p>
 */
public final class CDRConsoleReporter {
    private CDRConsoleReporter() { }

    public static void printAnalyzerFindings(String format, List<SecurityFinding> findings) {
        printFindings(format, "ANALYZER FINDINGS", "FINDING", findings);
    }

    public static void printFinalFindings(String format, List<SecurityFinding> findings) {
        printFindings(format, "FINAL FINDINGS", "FINAL FINDING", findings);
    }

    private static void printFindings(String format, String heading, String prefix,
                                      List<SecurityFinding> findings) {
        String safeFormat = format == null || format.isBlank() ? "CDR" : format.toUpperCase();
        List<SecurityFinding> safeFindings = findings == null ? List.of() : findings;

        System.out.println("=== " + safeFormat + " " + heading + ": " + safeFindings.size() + " ===");
        if (safeFindings.isEmpty()) {
            System.out.println(prefixFor(safeFormat, prefix) + ": NONE");
            return;
        }

        for (SecurityFinding finding : safeFindings) {
            if (finding == null) continue;
            System.out.println(prefixFor(safeFormat, prefix) + ": "
                    + finding.getClassification() + " | "
                    + finding.getType() + " | "
                    + finding.getDescription());
        }
    }

    private static String prefixFor(String format, String prefix) {
        return format + " " + prefix;
    }
}
