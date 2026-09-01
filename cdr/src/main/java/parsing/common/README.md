# Common Parsing Subsystem (`parsing.common`)

This package provides interfaces and shared utilities used by the DocShield parsing pipeline.

## 1. Purpose
The purpose of the `parsing.common` directory is to define the standard parser interface contract, implement the factory design pattern to resolve format parsers, and group reusable metadata extraction logic (core and application properties) that is common across OOXML files.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `DocumentParser.java` | Standard interface defining the parse contract for all formats. | `DocumentParser` (interface) |
| `ParserFactory.java` | Factory that maps the identified `Format` to a specific `DocumentParser` implementation. | `ParserFactory` |
| `HyperlinkExtractor.java` | Standard interface contract for format-specific link extraction. | `HyperlinkExtractor` (interface) |
| `CoreMetadataParser.java` | Extracts document properties (Title, Subject, Creator, Keywords, Description, Created, Modified) from OOXML `docProps/core.xml`. | `CoreMetadataParser` |
| `AppMetadataParser.java` | Extracts application properties (Application, AppVersion, Company, Manager, Pages, Words, Characters, Paragraphs, Lines) from OOXML `docProps/app.xml`. | `AppMetadataParser` |

## 3. How the Directory Fits into DocShield
- `Main` passes the detected file format to `ParserFactory.getParser()` to retrieve the appropriate parser.
- The returned parser implements `DocumentParser` and executes `parse(inputFile)` to return a unified `DocumentModel`.
- Individual format parsers (like `DOCXParser` or `XLSXParser`) delegate metadata extraction to `CoreMetadataParser` and `AppMetadataParser`.

```
                  Main.java
                      │
                      ▼ (Passes detected format)
              ParserFactory.getParser()
                      │
                      ▼ (Returns resolved implementation)
                DocumentParser (e.g. DOCXParser)
                      │
                      ├─► CoreMetadataParser (Reads docProps/core.xml)
                      ├─► AppMetadataParser  (Reads docProps/app.xml)
                      │
                      ▼ (Populates & Returns)
                DocumentModel
```

## 4. Dependencies
- `identification`
- `model.common`

## 5. External Libraries / APIs
- **Java XML DOM APIs (`javax.xml.parsers.DocumentBuilder`, `org.w3c.dom.Document`, `org.w3c.dom.NodeList`)**: Used to parse `core.xml` and `app.xml` files inside OOXML packages in a namespace-aware manner.
- **Java ZIP APIs (`java.util.zip.ZipFile`, `java.util.zip.ZipEntry`)**: Used to stream the individual metadata XML files from the archive.

## 6. Important Classes and Responsibilities
### `ParserFactory`
- **Resolution**: Maps `Format` enums to parser instances. It will throw an `IllegalArgumentException` if there is no parser available for the identified format.

### `CoreMetadataParser` & `AppMetadataParser`
- **Metadata Extraction**: Parse specific tags (such as `<Application>`, `<Words>`, `<creator>`, etc.) inside the zipped XML descriptors and load them as key-value pairs into the document model's metadata registry.
