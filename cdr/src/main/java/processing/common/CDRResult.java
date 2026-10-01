package processing.common;

import threat.common.SecurityFinding;

import java.nio.file.Path;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CDRResult {

    private final List<SecurityFinding> findings;
    private final List<String> actions;

    private final Path outputPath;

    private final boolean reconstructionSuccessful;
    private final boolean integrityPassed;

    private final boolean threatsRemoved;
    private final List<SecurityFinding> finalFindings;
    private final String inputSha256;
    private final String outputSha256;
    private final boolean originalCopied;


    public CDRResult(
            List<SecurityFinding> findings,
            List<String> actions,
            Path outputPath,
            boolean reconstructionSuccessful,
            boolean integrityPassed,
            boolean threatsRemoved) {

        this.findings =
                findings == null
                        ? new ArrayList<>()
                        : new ArrayList<>(findings);

        this.actions =
                actions == null
                        ? new ArrayList<>()
                        : new ArrayList<>(actions);

        this.outputPath =
                outputPath;

        this.reconstructionSuccessful =
                reconstructionSuccessful;

        this.integrityPassed =
                integrityPassed;

        this.threatsRemoved =
                threatsRemoved;
        this.finalFindings = new ArrayList<>();
        this.inputSha256 = null;
        this.outputSha256 = null;
        this.originalCopied = false;
    }


    public CDRResult(
            List<SecurityFinding> findings,
            List<String> actions,
            Path outputPath,
            boolean reconstructionSuccessful,
            boolean integrityPassed,
            boolean threatsRemoved,
            List<SecurityFinding> finalFindings) {

        this.findings = findings == null ? new ArrayList<>() : new ArrayList<>(findings);
        this.actions = actions == null ? new ArrayList<>() : new ArrayList<>(actions);
        this.outputPath = outputPath;
        this.reconstructionSuccessful = reconstructionSuccessful;
        this.integrityPassed = integrityPassed;
        this.threatsRemoved = threatsRemoved;
        this.finalFindings = finalFindings == null ? new ArrayList<>() : new ArrayList<>(finalFindings);
        this.inputSha256 = null;
        this.outputSha256 = null;
        this.originalCopied = false;
    }

    public CDRResult(
            List<SecurityFinding> findings, List<String> actions, Path outputPath,
            boolean reconstructionSuccessful, boolean integrityPassed, boolean threatsRemoved,
            List<SecurityFinding> finalFindings, String inputSha256, String outputSha256,
            boolean originalCopied) {
        this.findings = findings == null ? new ArrayList<>() : new ArrayList<>(findings);
        this.actions = actions == null ? new ArrayList<>() : new ArrayList<>(actions);
        this.outputPath = outputPath;
        this.reconstructionSuccessful = reconstructionSuccessful;
        this.integrityPassed = integrityPassed;
        this.threatsRemoved = threatsRemoved;
        this.finalFindings = finalFindings == null ? new ArrayList<>() : new ArrayList<>(finalFindings);
        this.inputSha256 = inputSha256;
        this.outputSha256 = outputSha256;
        this.originalCopied = originalCopied;
    }

    public List<SecurityFinding> getFinalFindings() {
        return Collections.unmodifiableList(finalFindings);
    }


    public List<SecurityFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }


    public List<String> getActions() {
        return Collections.unmodifiableList(actions);
    }


    public String getInputSha256() { return inputSha256; }

    public String getOutputSha256() { return outputSha256; }

    /** True when the output is an exact byte-for-byte copy of the original input. */
    public boolean isOriginalCopied() { return originalCopied; }

    /** True when an output artifact exists, whether copied unchanged or reconstructed. */
    public boolean isOutputReady() { return outputPath != null && Files.exists(outputPath) && Files.isRegularFile(outputPath); }

    public Path getOutputPath() {
        return outputPath;
    }


    public boolean hasThreats() {

        for (SecurityFinding finding : findings) {

            if (finding != null &&
                    finding.getClassification() ==
                            threat.common.FindingClassification.THREAT) {

                return true;
            }
        }

        return false;
    }


    /**
     * Returns true when any finding is a blocking security result.
     * Policy violations are blocking as well as confirmed threats.
     */
    public boolean hasBlockingFindings() {
        return containsBlocking(findings) || containsBlocking(finalFindings);
    }

    private static boolean containsBlocking(List<SecurityFinding> source) {
        if (source == null) return false;
        for (SecurityFinding finding : source) {
            if (finding != null &&
                    (finding.getClassification() == threat.common.FindingClassification.THREAT
                    || finding.getClassification() == threat.common.FindingClassification.POLICY_VIOLATION
                    || finding.getClassification() == threat.common.FindingClassification.SUSPICIOUS)) {
                return true;
            }
        }
        return false;
    }


    public boolean isThreatRemoved() {
        return threatsRemoved;
    }


    public boolean isReconstructionSuccessful() {
        return reconstructionSuccessful;
    }


    public boolean isIntegrityPassed() {
        return integrityPassed;
    }


    public String getThreatSummary() {

        StringBuilder result =
                new StringBuilder();

        for (SecurityFinding finding :
                findings) {

            if (finding == null ||
                    finding.getType() == null) {

                continue;
            }

            if (result.length() > 0) {
                result.append(", ");
            }

            result.append(
                    finding.getType()
            );
        }

        return result.length() == 0
                ? "NONE"
                : result.toString();
    }


    public threat.common.ThreatSeverity
    getHighestSeverity() {

        threat.common.ThreatSeverity highest =
                threat.common.ThreatSeverity.INFO;

        for (SecurityFinding finding :
                findings) {

            if (finding == null ||
                    finding.getSeverity() == null) {

                continue;
            }

            if (finding.getSeverity().ordinal()
                    > highest.ordinal()) {

                highest =
                        finding.getSeverity();
            }
        }

        return highest;
    }
}