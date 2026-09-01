# Shared Document Models (`model.common`)

This package defines format-independent object models that represent semantic contents and logical structure of a document.

## 1. Purpose
The purpose of the `model.common` directory is to define the intermediate representation (IR) schema of a document. Rather than operating on raw file bytes or format-specific vendor models directly, analyzers, sanitizers, and reporters operate on these unified schemas.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `ComponentCategory.java` | Enum for classifying document details and pipeline stages. | `ComponentCategory` (enum) |
| `DocumentModel.java` | The main compound container. Holds document metadata and collections of all extracted components. | `DocumentModel` |
| `MetadataModel.java` | Key-value store representing document metadata properties. | `MetadataModel` |
| `TextComponent.java` | Models text blocks, paragraphs (`TextParagraphComponent`), and runs (`TextRunComponent`) with formatting (font, size, weight, margins). | `TextComponent`, `TextParagraphComponent`, `TextRunComponent` |
| `ImageComponent.java` | Models inline/resource image components. | `ImageComponent` |
| `HyperlinkComponent.java` | Models hyperlinks with display text, target URLs, and positions. | `HyperlinkComponent` |
| `StructureComponent.java` | Models general document structure metadata (margins, page sizes, paragraphs, slides, sections). | `StructureComponent` |
| `EmbeddedObjectComponent.java` | Models embedded OLE files or binaries nested inside documents. | `EmbeddedObjectComponent` |
| `ThreatComponent.java` | Models detected threats within the generic document structure. | `ThreatComponent` |

## 3. How the Directory Fits into DocShield
Format-specific parsers extract data from documents and populate the `DocumentModel`. The processing layer reads the populated model to check for security vulnerabilities and output sanitization results.

```
Format-Specific Parsers
          │
          ▼ (Populates)
  ┌────────────────────────────────────────────────────────┐
  │                   DocumentModel                        │
  │  ┌──────────────────┬─────────────────┬─────────────┐  │
  │  │  TextComponents  │ ImageComponents │ Metadata    │  │
  │  ├──────────────────┼─────────────────┼─────────────┤  │
  │  │ HyperlinkComp... │ EmbeddedObjects │ Structure   │  │
  │  └──────────────────┴─────────────────┴─────────────┘  │
  └────────────────────────────────────────────────────────┘
          │
          ▼ (Read by)
ReportWriter / CDRProcessor
```

## 4. Dependencies
- `identification` (uses `FileInfo`)
- `model.pptx` (uses `PPTXTheme` and `PPTXLayout`)

## 5. External Libraries / APIs
None. Standard JDK libraries only (`java.util.List`, `java.util.Map`, `java.util.ArrayList`, `java.util.HashMap`).

## 6. Important Classes and Responsibilities
### `DocumentModel`
- Acts as a dual-representation container:
  1. **Legacy String Reports**: Maintains lists of Strings (`content`, `structure`, `threats`, etc.) to support legacy line-by-line report generation.
  2. **Modern IR**: Houses structured component lists (`textComponents`, `imageComponents`, etc.) suitable for object-level reconstruction.

### `TextComponent`
- Supports rich-text hierarchies:
  - Consists of multiple paragraphs (`TextParagraphComponent`).
  - Paragraphs consist of multiple styled runs (`TextRunComponent`) preserving font name, size, boldness, italics, underlining, alignment, and position boundaries.
  - Maintains helper aliases (`TextParagraph` and `TextRun`) to maintain backward compatibility with early parser versions.

## 7. Important Design Decisions
- **Rich Formatting Preservation**: The IR classes store geometry coordinates (`x`, `y`, `width`, `height`), page numbers, and structural attributes to ensure that reconstruction can place elements with visual fidelity.
- **Incremental Migration**: Maintains duplicate models (`List<String>` and `List<TextComponent>`) to allow reporting and reconstruction code to be written and tested independently.
- **Category Classification**: Uses `ComponentCategory` to tag document elements with stages of the CDR cycle (`IDENTIFICATION`, `METADATA`, `CONTENT`, `STRUCTURE`, `THREAT`, etc.).
