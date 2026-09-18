# Rich Text Format (RTF) Parser Subsystem (`parsing.rtf`)

The `parsing.rtf` package contains a custom lexical parser for Rich Text Format (`.rtf`) documents.

---

## 1. Current Release Status: CDR Deferred & Quarantined

> [!WARNING]
> **RTF CDR IS NOT ENABLED IN THIS RELEASE.**
> While this package provides lexical and semantic parsing components capable of extracting text, metadata, images, and embedded objects into a `DocumentModel`, **full Content Disarm and Reconstruction (CDR) for RTF is intentionally deferred**.
> 
> As enforced in [`Main.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/Main.java#L105-L110):
> ```java
> if (fileInfo.getFormat() == Format.RTF) {
>     quarantineAndExit(inputFile,
>             "RTF CDR is not enabled in this release.",
>             "RTF is not yet supported for safe disarm/reconstruction — file has been quarantined.");
>     return;
> }
> ```
> RTF files submitted to DocShield are automatically quarantined (exit code `2`) to prevent unsafe passthrough.

---

## 2. Parser Components

| File | Responsibility |
|---|---|
| [`RTFParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFParser.java) | Main entry point coordinating group-aware lexing and extraction into `DocumentModel`. |
| [`RTFContentParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFContentParser.java) | Group-aware lexical scanner tracking brace depth (`{`, `}`), hex escapes (`\'hh`), and skipping non-content destination groups (`\fonttbl`, `\colortbl`, `\stylesheet`, `\info`). |
| [`RTFResourceParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFResourceParser.java) | Scans for embedded hex-encoded images (`\pict`) and embedded OLE objects (`\object`). |
| [`RTFHyperlinkExtractor.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFHyperlinkExtractor.java) | Extracts URLs from RTF field structures (`{\field{\*\fldinst HYPERLINK ...}}`). |
| [`RTFMetadataParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFMetadataParser.java) | Extracts properties from the RTF `\info` group (title, author, creation date). |
