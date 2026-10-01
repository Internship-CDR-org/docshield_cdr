# CDR Processing Subsystem (`processing`)

The `processing` package orchestrates the end-to-end Content Disarm and Reconstruction (CDR) lifecycle across all supported document formats.

---

## 1. Architectural Purpose

The processing layer translates raw input files into safe, verified output artifacts. It coordinates:
1. Pre-sanitization threat analysis.
2. Capability disarming and sanitization.
3. Physical reconstruction or serialization.
4. Bounded post-reconstruction hardening loops.
5. Structural integrity validation and security re-analysis.
6. Clean copy optimization with SHA-256 byte-for-byte identity preservation when inputs are clean.

---

## 2. Directory Structure and Subsystem Map

```
processing/
├── README.md                      # This architectural document
├── common/                        # Shared contracts, result models, console reporting, and file utilities
│   ├── README.md
│   ├── CDRProcessor.java          # Core execution interface
│   ├── CDRResult.java             # Immutable outcome and telemetry model
│   ├── CDRConsoleReporter.java    # Standardized console logging
│   └── CDRFileUtil.java           # SHA-256 calculation and clean-copy utilities
├── docx/                          # DOCX pipeline orchestrator
│   └── DOCXCDRProcessor.java
├── pptx/                          # PPTX pipeline orchestrator
│   └── PPTXCDRProcessor.java
├── xlsx/                          # XLSX pipeline orchestrator
│   └── XLSXCDRProcessor.java
├── doc/                           # Legacy DOC -> sandboxed conversion -> DOCX CDR
│   └── DOCCDRProcessor.java
├── ppt/                           # Legacy PPT -> sandboxed conversion -> PPTX CDR
│   └── PPTCDRProcessor.java
├── xls/                           # Legacy XLS -> sandboxed conversion -> XLSX CDR
│   └── XLSCDRProcessor.java
├── pdf/                           # Multi-pass PDF disarmer & verifier
│   └── PDFCDRProcessor.java
├── rtf/                           # Native RTF disarm/reconstruction
│   └── RTFCDRProcessor.java
└── zip/                           # Recursive ZIP container CDR
    └── ZipCDRProcessor.java
```

---

## 3. High-Level Processing Lifecycle

```
                    Input File Path
                          │
                          ▼
            Format Identification & Routing
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
   Modern Formats                    Legacy Formats
  (DOCX, PPTX, XLSX, PDF)            (DOC, PPT, XLS)
         │                                 │
         │                        1. Pre-Conversion Analysis
         │                           (inspect legacy binary)
         │                                 │
         │                        2. Sandboxed Conversion
         │                           (LibreOffice in SubprocessSandbox)
         │                                 │
         ▼                                 ▼
  Threat Analysis ◄────────────── Converted Modern OOXML
         │
         ├─► Clean? ────► Copy Original (Exact SHA-256) ──► PASS
         │
         ▼ (Actionable Findings)
   Sanitization & Disarming
         │
   Reconstruction / Serialization
         │
   Post-Reconstruction Loop (Up to 3 passes)
         │
         ├─► Structural Integrity Validation (validation.*)
         ├─► Security Re-analysis (threat.*)
         └─► Embedded Content Inspection
         │
         ▼
   Final Gate: Both Passed? 
         ├── YES ──► Output Released (exit 0)
         └── NO  ──► Output Deleted + Quarantine (exit 2)
```


## 4. ZIP Container CDR

`ZipCDRProcessor` treats ZIP archives as untrusted containers rather than as automatically safe files. It applies global limits on entry count and decompressed bytes, rejects path traversal, recursively processes nested ZIPs up to a bounded depth, routes supported document entries through the existing CDR processors, removes known executable/script payloads and unsupported entries, then reconstructs and reopens the output archive for validation.

The top-level `Main` class generates a container-level ZIP CDR report because ZIP archives do not use the document `DocumentModel` parser pipeline.
