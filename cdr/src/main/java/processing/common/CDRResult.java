package processing.common;

import threat.common.SecurityFinding;

import java.nio.file.Path;
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
    }


    public List<SecurityFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }


    public List<String> getActions() {
        return Collections.unmodifiableList(actions);
    }


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