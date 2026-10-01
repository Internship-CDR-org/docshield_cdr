# Legacy PPT Processing Pipeline (`processing.ppt`)

The `processing.ppt` package contains the Content Disarm and Reconstruction driver for legacy Microsoft PowerPoint binary presentations (`.ppt` - PowerPoint 97-2003 Compound File Binary Format).

---

## 1. Architectural Philosophy: Pre-Conversion Analysis + Sandboxed CDR

Legacy PowerPoint files (`.ppt`) contain complex OLE2 stream structures (`PowerPoint Document`, `Current User`, `Pictures`, `_VBA_PROJECT_CUR`). In addition to standard VBA macros and embedded objects, legacy PPT presentations can contain binary action records (`InteractiveInfoAtom`, type `0x0FF3`) that trigger executable execution (`ppaction://program`), macro execution, or OLE verb activation upon mouse click or hover.

DocShield guarantees security through a multi-stage process:

```
Legacy .ppt Input
       │
       ▼ 1. Pre-Conversion Inspection (PPTThreatAnalyzer)
       │    • Scan OLE storages for VBA macro streams
       │    • Parse binary UserEditAtoms and InteractiveInfoAtoms for macro/program click actions
       │    • Scan for Ole10Native embedded executables
       │
       ▼ 2. Sandboxed LibreOffice Conversion (PPTToPPTXConverter)
       │    • Executes inside SubprocessSandbox in isolated temporary workspace
       │    • Converts binary PPT into modern PresentationML PPTX
       │
       ▼ 3. Modern PPTX CDR (PPTXCDRProcessor)
       │    • Full threat analysis, action disarming, embedded package sanitization, and reconstruction
       │    • Post-reconstruction integrity verification
       │
       ▼ 4. Findings & Action Aggregation
       │    • Merges pre-conversion legacy findings with modern disarming actions
       │
       ▼ 5. Workspace Cleanup & Release
            • Purges temporary conversion workspace
            • Emits clean, verified modern PPTX artifact
```

---

## 2. Core Implementation: `PPTCDRProcessor`

- [`PPTCDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/ppt/PPTCDRProcessor.java) implements [`CDRProcessor`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/common/CDRProcessor.java).
- Performs pre-conversion threat analysis via [`PPTThreatAnalyzer`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/threat/ppt/PPTThreatAnalyzer.java).
- Executes sandboxed conversion to PPTX via [`PPTToPPTXConverter.convert`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/ppt/PPTToPPTXConverter.java) and [`LegacyOfficeConverter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/legacy/LegacyOfficeConverter.java).
- Processes converted artifact through [`PPTXCDRProcessor.process(converted, output, false)`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/processing/pptx/PPTXCDRProcessor.java).
- Guarantees complete temporary workspace removal in a `finally` block.
- Emits a sanitized, verified modern `.pptx` presentation.
