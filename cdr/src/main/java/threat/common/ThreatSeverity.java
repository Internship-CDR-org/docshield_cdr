package threat.common;


/**
 * Severity assigned to a security finding.
 *
 * This describes the seriousness of a finding.
 *
 * It does NOT by itself mean that content must be removed.
 */
public enum ThreatSeverity {

    INFO,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}