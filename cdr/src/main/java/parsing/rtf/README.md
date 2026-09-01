# Rich Text Format (RTF) Parser Subsystem (`parsing.rtf`)

This package is responsible for parsing Rich Text Format (`.rtf` files).

## 1. Purpose
The purpose of the `parsing.rtf` directory is to parse legacy RTF documents. It implements a custom lexical analyzer and parser that scans group hierarchies, removes RTF control words, reads metadata, and extracts inline images, links, and embedded files into the unified `DocumentModel`.

## 2. Files in this Directory
| File | Responsibility | Important Classes/Interfaces/Enums |
| :--- | :--- | :--- |
| `RTFParser.java` | Core driver class. Directs the text, resource, link, and metadata parsers. | `RTFParser` |
| `RTFContentParser.java` | Scans visible text from the RTF file using a group-aware lexical loop. | `RTFContentParser` |
| `RTFMetadataParser.java` | Parses key-value properties from the RTF metadata block. | `RTFMetadataParser` |
| `RTFResourceParser.java` | Extracts embedded images (`pict`) and embedded files (`object`). | `RTFResourceParser` |
| `RTFHyperlinkExtractor.java` | Extracts hyperlinks from the RTF field structures. | `RTFHyperlinkExtractor` |

## 3. How the Directory Fits into DocShield
- `ParserFactory` resolves the `RTFParser` when processing a `.rtf` file.
- The parser feeds the input file through the content, resource, hyperlink, and metadata helpers to build the `DocumentModel`.

```
                  Input RTF File
                         │
                         ▼
                     RTFParser
                         ├─► RTFContentParser (Group-aware scanner)
                         ├─► RTFResourceParser (pict & object extraction)
                         ├─► RTFHyperlinkExtractor (Field links)
                         └─► RTFMetadataParser (Info group properties)
                         ▼
                   DocumentModel
```

## 4. Dependencies
- `parsing.common`
- `model.common`

## 5. External Libraries / APIs
None. Standard JDK libraries only. Reads files using `StandardCharsets.ISO_8859_1`.

## 6. Important Classes and Responsibilities
### `RTFContentParser`
- **Group Tracking**: Manages a stack depth accumulator to track nested RTF groups (`{` and `}`).
- **Control Word Filtering**: Detects control sequences starting with `\` and skips parameters. Translates control words like `\par` and `\line` to newlines.
- **Hex Decoding**: Decodes hex escapes (e.g. `\'e9`) into Unicode characters.
- **Destination Filtering**: Ignores formatting destination groups (`fonttbl`, `colortbl`, `stylesheet`, `info`, `generator`, `listtable`, `listoverridetable`, `revtbl`, `xmlnstbl`, `header`, `footer`).

### `RTFResourceParser`
- **Asset Extraction**: Scans the RTF stream for asset destination headers:
  - `pict` groups: Decodes inline hex-encoded images.
  - `object` groups: Decodes inline OLE objects or embedded files.
