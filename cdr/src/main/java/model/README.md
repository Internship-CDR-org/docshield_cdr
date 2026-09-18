# Data Model Subsystem (`model`)

The `model` package defines the core in-memory abstractions used throughout the DocShield CDR lifecycle.

---

## 1. Subpackage Breakdown

```
model/
├── README.md                      # This architectural document
├── common/                        # High-level Semantic Intermediate Representation (IR)
│   ├── DocumentModel.java         # Root container for semantic document elements
│   ├── MetadataModel.java         # Document metadata properties (author, title, etc.)
│   ├── StructureComponent.java    # Document structure blocks (sections, paragraphs, slides, sheets)
│   ├── TextComponent.java         # Text runs and styled content
│   ├── ImageComponent.java        # Extracted static image assets
│   ├── HyperlinkComponent.java    # Hyperlink targets and anchor text
│   ├── EmbeddedObjectComponent.java # Embedded OLE/payload references
│   ├── ThreatComponent.java       # Visual indicator of stripped threats
│   └── ComponentCategory.java     # Component classification enum
├── ooxml/                         # Physical OPC / OOXML Package Representation
│   ├── OOXMLPackage.java          # In-memory package container holding parts and relationships
│   ├── OOXMLPart.java             # Individual physical part (XML, media, binary)
│   └── OOXMLRelationship.java     # Relationship tuple (Id, Source, Type, Target, Mode)
└── pptx/                          # PowerPoint Semantic Models (Layout & Themes)
    ├── PPTXLayout.java            # Slide layout metadata
    ├── PPTXLayoutElement.java     # Placeholder element definitions
    └── PPTXTheme.java             # Presentation theme color and font definitions
```

---

## 2. Distinction: Physical Package Model vs Semantic IR

- **`model.ooxml` (Physical Package Model)**: The primary data structure for CDR disarming and reconstruction. Operates on raw byte arrays, relationship graphs, and XML buffers without lossy abstraction.
- **`model.common` (Semantic IR)**: A read-only representation extracted after CDR completion to drive human-readable audit reporting and structure summaries in [`ReportWriter`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/reporting/ReportWriter.java).
