package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

public enum PayloadType {

    UNKNOWN,

    WINDOWS_BATCH_SCRIPT,

    WINDOWS_COMMAND_SCRIPT,

    POWERSHELL_SCRIPT,

    JAVASCRIPT,

    VBS_SCRIPT,

    VBA_SOURCE,

    PE_EXECUTABLE,

    ELF_EXECUTABLE,

    PDF_DOCUMENT,

    ZIP_ARCHIVE,

    OFFICE_DOCUMENT,

    IMAGE,

    SVG,

    TEXT
}