# DOCX Security Surface Inventory

| Surface | Detection | Action | Preservation boundary |
|---|---|---|---|
| VBA project | `word/vbaProject.bin` and relationship | Remove part + relationships + content type | Whole active-code part |
| ActiveX | `word/activeX/*` and relationships | Remove unsafe control parts | Whole active-control part |
| OLE | OLE/package inspection | Preserve if only observed; remove when active/native threat confirmed | OLE object |
| Native executable in embeddings | filename/signature | Remove containing unsafe part | Embedded payload |
| DDE/DDEAUTO | Word field instructions, including fragmented `w:instrText` | Remove field instructions | Cached/displayed result preserved |
| INCLUDE/INCLUDETEXT | Word field instructions | Remove field instructions | Cached/displayed result preserved |
| INCLUDEPICTURE | Word field instructions | Remove field instructions | Cached/displayed result preserved |
| LINK/IMPORT | Word field instructions | Remove field instructions | Cached/displayed result preserved |
| External attached template | `attachedTemplate` relationship with external target | Remove relationship/reference | Main document remains |
| Macro-enabled attached template | Internal `attachedTemplate` target is `.dotm`/macro-enabled | Remove relationship + template part | Main document remains |
| Mail-merge source | `mailMergeSource` relationship | Remove relationship/reference | Document text/fields remain |
| Mail-merge recipient data | `recipientData` relationship | Remove relationship/configuration | Document remains |
| Automatic field update | `word/settings.xml` `w:updateFields=true` | Remove setting | Other settings remain |
| altChunk external | `aFChunk` external relationship | Remove relationship | Main document remains |
| altChunk active HTML/XHTML | HTML/XHTML active constructs | Remove imported-content part + relationship | Main document remains |
| altChunk macro-enabled content | Macro-enabled content type | Remove imported-content part + relationship | Main document remains |
| Normal HTTPS hyperlink | External hyperlink relationship | Observe/preserve | Link remains |
| Dangerous URI | Relationship target scheme | Remove relationship/reference | Surrounding content preserved |
| XML DTD/ENTITY | Secure XML analysis | Reject/sanitize | Package safety boundary |
| Invalid relationship reference | Package graph validation | Remove dangling reference | Other content preserved |
| Path traversal | Package path validation | Reject | Package safety boundary |
| Nested OOXML | Recursive OOXML inspection | Recursively sanitize supported nested package | Preserve clean nested package |
| Uninspectable nested content | Depth/size/count safeguards | Fail closed | Untrusted content not preserved |
