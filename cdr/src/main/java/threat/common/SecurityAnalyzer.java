package threat.common;

import java.util.List;


/**
 * Universal contract for security analyzers used by DocShield.
 *
 * An analyzer examines already-parsed content and produces
 * security findings.
 *
 * The analyzer MUST NOT modify the original content.
 *
 * Format-specific parsing belongs outside this interface.
 */
public interface SecurityAnalyzer<T> {

    /**
     * Analyze the supplied content.
     *
     * @param content parsed content to inspect
     * @return security findings discovered during analysis
     */
    List<SecurityFinding> analyze(T content);
}