package threat.common;

import java.util.List;

/** Common threat-analysis contract shared by every document format. */
public interface ThreatAnalyzer<T> {
    List<SecurityFinding> analyze(T document);
}
