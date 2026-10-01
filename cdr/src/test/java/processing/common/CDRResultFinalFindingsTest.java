package processing.common;

import org.junit.jupiter.api.Test;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CDRResultFinalFindingsTest {
    @Test
    void preservesInitialAndFinalFindingsSeparately() {
        SecurityFinding initial = new SecurityFinding(
                FindingClassification.THREAT, ThreatType.VBA_PROJECT, ThreatSeverity.HIGH,
                null, "Macros/VBA", null, "macro", "VBA project detected", "Remove it");
        SecurityFinding remaining = new SecurityFinding(
                FindingClassification.THREAT, ThreatType.DANGEROUS_ACTION, ThreatSeverity.CRITICAL,
                null, "word/document.xml", null, "action", "dangerous action remains", "Remove it");

        CDRResult result = new CDRResult(
                List.of(initial), List.of("Removed VBA"), null,
                true, true, false, List.of(remaining));

        assertEquals(1, result.getFindings().size());
        assertEquals(ThreatType.VBA_PROJECT, result.getFindings().get(0).getType());
        assertEquals(1, result.getFinalFindings().size());
        assertEquals(ThreatType.DANGEROUS_ACTION, result.getFinalFindings().get(0).getType());
        assertTrue(result.hasThreats());
        assertTrue(result.hasBlockingFindings());
    }

    @Test
    void suspiciousFindingsAreBlocking() {
        CDRResult result = new CDRResult(
                List.of(new SecurityFinding(
                        FindingClassification.SUSPICIOUS, ThreatType.INVALID_RELATIONSHIP, ThreatSeverity.HIGH,
                        null, "word/document.xml", "rIdBad", "dangling", "invalid relationship", "Remove it")),
                List.of(), null, true, true, false, List.of());

        assertTrue(result.hasBlockingFindings());
    }

    @Test
    void cleanFinalFindingsRepresentSuccessfulPostCdrVerification() {
        CDRResult result = new CDRResult(
                List.of(new SecurityFinding(
                        FindingClassification.THREAT, ThreatType.VBA_PROJECT, ThreatSeverity.HIGH,
                        null, "Macros/VBA", null, "macro", "VBA project detected", "Remove it")),
                List.of("Disarmed VBA during conversion"), null,
                true, true, true, List.of());

        assertTrue(result.hasThreats());
        assertTrue(result.isThreatRemoved());
        assertTrue(result.getFinalFindings().isEmpty());
    }
}
