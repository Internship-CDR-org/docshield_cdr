# OOXML Integrity Validation Subsystem (`validation.ooxml`)

This package is responsible for verifying the internal logical integrity of reconstructed Open Packaging Convention (OPC) / Office Open XML (OOXML) documents.

## 1. Purpose
The purpose of the `validation.ooxml` directory is to protect against document corruption. When DocShield disarms a document by removing threats (like macro parts or OLE files) and serializing the remaining elements, this validator checks that the output package remains logically sound (e.g. that all internal file references resolved successfully and that the file contains required content descriptors).

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `OOXMLIntegrityValidator.java` | Scans package parts and relationship lists to check that target files exist and that relationship definitions are valid and unique. | `OOXMLIntegrityValidator` |

## 3. How the Directory Fits into DocShield
- `DOCXCDRProcessor` and `XLSXCDRProcessor` invoke `OOXMLIntegrityValidator` after rewriting the output file.
- If validation fails, `CDRResult` records `integrityPassed = false`.

```
  Output File written
          │
          ▼ (Re-read into)
     OOXMLPackage
          │
          ▼ (Validated by)
  OOXMLIntegrityValidator.validate()
          │
          ├─► Confirm [Content_Types].xml is present
          ├─► Confirm all parts have valid names
          ├─► Confirm all relationships have unique IDs
          └─► Confirm all internal relationship targets point to existing parts
          │
          ▼ (Outcome recorded in)
      CDRResult (integrityPassed flag)
```

## 4. Dependencies
- `model.ooxml`

## 5. External Libraries / APIs
None. Standard JDK libraries only (`java.util.Set`, `java.util.HashSet`).

## 6. Important Classes and Responsibilities
### `OOXMLIntegrityValidator`
- **Internal Validity Check (`validate(packageData)`)**:
  - Ensures `[Content_Types].xml` is present and the content types map is populated.
  - Ensures relationships have IDs, types, and targets.
  - Checks relationship key uniqueness (uniqueness of the combination of source part and relationship ID).
  - Resolves internal target paths (supporting relative paths, e.g. mapping `../media/image1.png` relative to `word/document.xml` to `word/media/image1.png`) and checks that the targeted files exist in the package.
- **Preservation Check (`validate(original, reconstructed)`)**:
  - Compares the reconstructed package against the original package to ensure that no foreign parts were injected (all parts in the reconstructed package must have originated from the original package).
