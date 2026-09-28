# DOCX Security Pass 2

This pass completes the Word-specific field/relationship/template layer on top of the common OOXML security engine.

## Implemented

- Fragmented Word field-code detection across multiple `w:instrText` elements.
- DDE and DDEAUTO detection and instruction-only sanitization.
- INCLUDE, INCLUDETEXT, INCLUDEPICTURE, LINK and IMPORT field detection.
- External-field instruction removal while preserving cached/displayed result runs.
- `w:updateFields` automatic-update removal.
- Attached-template relationship detection.
- External attached-template removal.
- Internal macro-enabled `.dotm` attached-template removal, including its relationship and package part.
- Word mail-merge source/recipient relationship detection.
- External mail-merge relationship removal.
- Word altChunk (`aFChunk`) inspection.
- External altChunk relationship removal.
- Internal active HTML/XHTML or macro-enabled altChunk removal.
- Safe/ordinary embedded content remains observation-only unless a blocking threat is confirmed.
- Common package relationship/content-type cleanup remains responsible for reconstruction.

## Preservation rule

A field threat is sanitized at the instruction level where possible. Cached result content is preserved. A container such as an attached template or active altChunk is removed only when the contained capability is confirmed unsafe.

## Verification

Dependency-free security/package classes compile with JDK 21. Real DOCX samples were processed through reader -> analyzer -> sanitizer -> writer -> rereader -> integrity validator.

Full Maven/JUnit execution still requires the project's Maven dependencies to be available.
