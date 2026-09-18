# Legacy DOC Processing Pipeline (`processing.doc`)

The `processing.doc` package contains the Content Disarm and Reconstruction driver for legacy Microsoft Word binary documents (`.doc` - Word 97-2003 Compound File Binary Format).

---

## 1. Architectural Philosophy: Pre-Conversion Analysis + Sandboxed CDR

Legacy binary formats pose severe security risks because the binary parsing engine in office suites is complex and historically vulnerable to memory corruption. Furthermore, converting a legacy document directly into an OOXML document without pre-analysis risks silently dropping malicious macros or OLE exploit traces, making the original threat invisible to downstream reports.

DocShield implements a rigorous 5-step pipeline:

```
Legacy .doc Input
       │
       ▼ 1. Pre-Conversion Inspection (DOCThreatAnalyzer)
       │    • Ingest OLE2 streams (WordDocument, 1Table, Macros, ObjectPool)
       │    • Record all VBA, OLE, and macro findings BEFORE conversion
       │
       ▼ 2. Sandboxed LibreOffice Conversion (DOCToDOCXConverter)
       │    • Runs inside SubprocessSandbox / Bubblewrap / Docker
       │    • Converts legacy DOC to intermediate modern DOCX in ephemeral workspace
       │
       ▼ 3. Modern DOCX CDR (DOCXCDRProcessor)
       │    • Full threat analysis, sanitization, recursive embedded CDR, reconstruction
       │    • Post-reconstruction integrity verification
       │
       ▼ 4. Findings & Action Aggregation
       │    • Merges pre-conversion legacy findings with post-conversion actions
       │    • Verifies output usability and integrity
       │
       ▼ 5. Workspace Cleanup & Safe Release
            • Securely deletes temporary conversion directory tree
            • Emits final verified DOCX artifact
```

---

## 2. Core Implementation: `DOCCDRProcessor`

- [`DOCCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/doc/DOCCDRProcessor.java) implements [`CDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRProcessor.java).
- Analyzes the input `.doc` file using [`DOCThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/doc/DOCThreatAnalyzer.java) to record original threats.
- Invokes [`DOCToDOCXConverter.convert`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/doc/DOCToDOCXConverter.java) (backed by [`LegacyOfficeConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/legacy/LegacyOfficeConverter.java)) to convert `.doc` to `.docx` in an isolated sandbox workspace.
- Pipes the converted `.docx` into [`DOCXCDRProcessor.process(converted, output, false)`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/docx/DOCXCDRProcessor.java).
- Ensures that temporary workspace files are cleanly deleted in a `finally` block via `deleteConvertedWorkspace`.
- Output SHA-256 naturally differs from input SHA-256 because a new, modernized, sanitized `.docx` package is produced.
