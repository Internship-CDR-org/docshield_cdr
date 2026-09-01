package sanitization.common;

import threat.common.SecurityFinding;

import java.util.List;

/** Common sanitizer contract shared by every document format. */
public interface Sanitizer<T> {
    List<String> sanitize(T document, List<SecurityFinding> findings);
}
