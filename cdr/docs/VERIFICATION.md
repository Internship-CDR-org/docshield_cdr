# Verification Record

Date: 2026-09-01

## Performed in this environment

- Exhaustive source-tree inventory of production/test Java files and project folders.
- Removed the duplicate physical PPTX package model and PPTX package reader/writer.
- Verified no Java source imports or references the deleted physical PPTX package classes.
- Compiled the extended non-POI portion of the source tree with JDK 21.
- Compiled the common OOXML model, reader, writer, analyzer, sanitizer, validator and DOCX/XLSX processors.
- Ran the common CDR path against the supplied real DOCX/PPTX/XLSX samples.
- Verified ZIP integrity for reconstructed sample outputs.
- Verified reconstructed OOXML package integrity with `OOXMLIntegrityValidator`.
- Verified VBA removal and content-type cleanup on the supplied XLSX/DOCX macro samples.
- Verified embedded OLE/executable-boundary removal on the supplied PPTX embedded-BAT sample.
- Verified ordinary HTTPS hyperlinks remain preserved.
- Verified synthetic DDE and XML DOCTYPE/ENTITY constructs are detected and disarmed.
- Verified synthetic dangerous external relationships are removed together with relationship references.
- Verified synthetic PowerPoint program actions are removed together with their relationship IDs.
- Verified synthetic PowerPoint VBA, ActiveX, `ctrlProps`, and active-SVG structures are disarmed.
- Verified the supplied `pptx_embedded_bat.pptx` sample is reconstructed with its embedded OLE part removed and package integrity passing.
- Verified presentation samples preserve ordinary HTTPS hyperlink relationships during reconstruction.

## Build and Test Status

The project builds and passes tests using Apache Maven 3.9.9 and OpenJDK 21 LTS (`mvn clean test`). All 104 automated tests pass with 0 failures, 0 errors, and 0 skipped tests.
