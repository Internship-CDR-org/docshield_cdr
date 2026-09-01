package threat.common;

import model.ooxml.OOXMLPart;


/**
 * Represents a security/content finding produced during
 * document inspection.
 *
 * A SecurityFinding is an observation about package content.
 *
 * It does NOT modify the package.
 */
public class SecurityFinding {

    private final FindingClassification classification;

    private final ThreatType type;

    private final ThreatSeverity severity;

    private final OOXMLPart part;

    private final String sourcePart;

    private final String relationshipId;

    private final String evidence;

    private final String description;

    private final String recommendedAction;


    public SecurityFinding(
            FindingClassification classification,
            ThreatType type,
            ThreatSeverity severity,
            OOXMLPart part,
            String sourcePart,
            String relationshipId,
            String evidence,
            String description,
            String recommendedAction) {

        this.classification =
                classification;

        this.type =
                type;

        this.severity =
                severity;

        this.part =
                part;

        this.sourcePart =
                sourcePart;

        this.relationshipId =
                relationshipId;

        this.evidence =
                evidence;

        this.description =
                description;

        this.recommendedAction =
                recommendedAction;
    }


    public FindingClassification getClassification() {
        return classification;
    }


    public ThreatType getType() {
        return type;
    }


    public ThreatSeverity getSeverity() {
        return severity;
    }


    public OOXMLPart getPart() {
        return part;
    }


    public String getPartName() {

        return part == null
                ? null
                : part.getPartName();
    }


    public String getSourcePart() {
        return sourcePart;
    }


    public String getRelationshipId() {
        return relationshipId;
    }


    public String getEvidence() {
        return evidence;
    }


    public String getDescription() {
        return description;
    }


    public String getRecommendedAction() {
        return recommendedAction;
    }


    @Override
    public String toString() {

        return "SecurityFinding{" +
                "classification=" +
                classification +
                ", type=" +
                type +
                ", severity=" +
                severity +
                ", part='" +
                getPartName() +
                '\'' +
                ", sourcePart='" +
                sourcePart +
                '\'' +
                ", relationshipId='" +
                relationshipId +
                '\'' +
                ", evidence='" +
                evidence +
                '\'' +
                ", description='" +
                description +
                '\'' +
                ", recommendedAction='" +
                recommendedAction +
                '\'' +
                '}';
    }
}