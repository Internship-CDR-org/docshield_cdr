# Common Processing Subsystem (`processing.common`)

The `processing.common` package defines the core execution contracts, immutable result records, telemetry models, and low-level file utilities for the DocShield CDR engine.

---

## 1. Core Classes & Responsibilities

### `CDRProcessor` (Interface)
Contract implemented by all format-specific processors:
```java
public interface CDRProcessor {
    CDRResult process(Path inputFile, Path outputFile) throws Exception;
}
```

### `CDRResult` (Result Model)
Immutable data container capturing complete processing state:
- **`findings`**: List of initial [`SecurityFinding`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/common/SecurityFinding.java) objects discovered during first-pass analysis.
- **`actions`**: List of human-readable disarming and sanitization actions performed.
- **`outputFile`**: Final path to the generated output file.
- **`reconstructionSuccessful`**: Boolean flag confirming physical file generation.
- **`integrityPassed`**: Boolean flag confirming structural validation passed.
- **`threatsRemoved`**: Boolean flag confirming all actionable threats were eliminated and verified absent.
- **`finalFindings`**: List of residual findings discovered on the re-read output file.
- **`inputSha256`**: SHA-256 hash of the input file before processing.
- **`outputSha256`**: SHA-256 hash of the output file after processing.
- **`cleanCopy`**: Boolean flag indicating whether the file was clean and copied directly without reconstruction.

#### Key Query Methods on `CDRResult`
- `hasBlockingFindings()`: Returns `true` if any initial finding has classification `THREAT`, `POLICY_VIOLATION`, or `SUSPICIOUS`.
- `hasRemainingBlockingFindings()`: Returns `true` if any final re-analysis finding remains blocking.
- `isOutputReady()`: Confirms `outputFile` exists and has non-zero length on disk.
- `isSafeToRelease()`: Convenience method asserting `isOutputReady() && isIntegrityPassed() && isThreatRemoved() && !hasRemainingBlockingFindings()`.

### `CDRConsoleReporter`
Static utility providing uniform CLI output formatting for analyzer findings and final post-CDR verification results.

### `CDRFileUtil`
Static file utility providing:
- **`sha256(Path file)`**: Computes the hexadecimal SHA-256 hash of any file using `MessageDigest.getInstance("SHA-256")`.
- **`copyOriginal(Path src, Path dst)`**: Atomically copies a clean input file to the destination path, creating parent directories if needed, and setting standard copy options (`REPLACE_EXISTING`, `COPY_ATTRIBUTES`).
