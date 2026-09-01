package threat.common;


/**
 * Describes how a security finding should be interpreted.
 *
 * IMPORTANT:
 *
 * The existence of a finding does NOT automatically mean
 * that the content is malicious.
 */
public enum FindingClassification {

    /**
     * Something was observed but is not inherently dangerous.
     */
    OBSERVATION,


    /**
     * Content violates an explicit CDR policy.
     */
    POLICY_VIOLATION,


    /**
     * Content has characteristics that require further analysis.
     */
    SUSPICIOUS,


    /**
     * Content has been determined to be dangerous.
     */
    THREAT
}