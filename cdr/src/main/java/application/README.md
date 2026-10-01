# Application Subsystem (`application`)

The `application` package contains CLI error translation and operator message formatting utilities for DocShield CDR.

---

## 1. Core Classes & Responsibilities

### `UserFacingError`
[`UserFacingError`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/application/UserFacingError.java) is a static utility that maps internal runtime exceptions and I/O failures into clear, actionable operator messages suitable for terminal output and quarantine logs.

#### Key Functions
- **`message(Throwable throwable, Path input, Path output)`**: Inspects exception types (such as `AccessDeniedException`, `NoSuchFileException`, `ZipException`, or format corruption) and returns an informative explanation of why the input could not be processed safely.
- **`outputMessage(Throwable throwable, Path output)`**: Translates output path errors (e.g. read-only destination directory or permission denial) into operator error guidance without attributing the fault to the input file.
