# DocShield Sanitization Specification

## 1. Overview

DocShield applies surgical, format-aware sanitization to eliminate active, dangerous, or policy-violating components from documents while preserving visual presentation, layout, text formatting, and benign media.

---

## 2. Format-Specific Sanitization Rules

### 2.1 OOXML (`DOCX`, `PPTX`, `XLSX`)

#### Macro & Active Content Disarming
- **VBA Projects**: Parts matching `word/vbaProject.bin`, `ppt/vbaProject.bin`, `xl/vbaProject.bin` are purged along with their `.rels` entries and `[Content_Types].xml` overrides.
- **ActiveX Controls**: Parts matching `/activeX/` directories or ActiveX content types (`application/vnd.ms-office.activeX+xml`) are removed.
- **XLM 4.0 Macros**: Excel dialog sheets and macro sheets (`xl/macrosheets/`) are purged.

#### Dynamic Data Exchange (DDE)
- **Word**: Field instructions containing `DDE` or `DDEAUTO` across single or fragmented `w:instrText` / `w:fldSimple` elements are stripped; displayed text in `w:fldResult` is preserved.
- **Excel**: Formula elements (`<f>`) and defined names containing DDE expressions or command pipes (`cmd|...`, `powershell|...`) are removed; cached cell values (`<v>`) are cleared.

#### Relationships & Dangerous Actions
- **PowerPoint Actions**: Elements with `ppaction://` protocols or `actionType="runprogram"` / `runmacro` / `oleverb` are stripped from slide XML and relationship tables.
- **External Hyperlinks**: Hyperlinks with dangerous protocols (`file:`, `javascript:`, `vbscript:`, `data:`, `ms-msdt:`, `shell:`, UNC `\\\\`) are removed from relationships.
- **External References**: Word `attachedTemplate` and Excel external workbook connections (`xl/externalLinks/`) are pruned.

#### Embedded OOXML Packages
- Nested packages are extracted, analyzed, sanitized via `RecursiveOOXMLSanitizer`, reconstructed in memory, and updated in-place.
- If a nested package cannot be inspected safely within configured limits (depth 4, max 256 packages), it is removed.

---

### 2.2 Portable Document Format (`PDF`)

#### Actions & Trigger Neutralization
- **Document Catalog**: Strips `/OpenAction`, `/AA` (additional actions), and `/Names` trees for `JavaScript` and `EmbeddedFiles`.
- **Pages**: Traverses page annotations (`/Annots`) and removes `/Launch`, `/GoToR`, `/GoToE`, `/SubmitForm`, `/ImportData`, `/RichMediaExecute`, `/Movie`, `/Sound`, and dangerous `/URI` actions.
- **Active Annotations**: Purges `/FileAttachment`, `/RichMedia`, `/3D`, `/Movie`, `/Sound`, and `/Screen` annotations.

#### Form & Stream Sanitization
- **XFA Forms**: Purges active XML Forms Architecture trees from `/AcroForm`.
- **Digital Signatures**: Removes digital signature fields (`/Sig`, `/ByteRange`, `/Contents`) as CDR reconstruction invalidates cryptographic seals.
- **Executable Streams**: Inspects decoded stream bytes for executable headers (`MZ`, `ELF`, `Mach-O`, shell scripts) and empties the stream payload.

---

### 2.3 Rich Text Format (`RTF`)

#### Embedded Objects & Exploit Disarming
- **OLE Objects**: Scans for `{\object` groups and removes active OLE controls (including Equation Editor buffer overflow vectors). If a static picture exists in `\result`, it is preserved.
- **Template Injection**: Removes `{\*\template ...}` control groups.
- **DDE Fields**: Strips `\field` groups with `DDE` / `DDEAUTO` while extracting static cached text from `\fldrslt`.
- **Dangerous Hyperlinks**: Neutralizes dangerous URI schemes to safe `#disarmed` anchors.
- **Embedded Fonts**: Purges `{\fontemb ...}` groups.

---

## 3. Clean-File Integrity Policy

```
                    +-----------------------------+
                    |       Threat Analysis       |
                    +-----------------------------+
                                   |
                     +-------------+-------------+
                     |                           |
             [No Threats Found]          [Threats Detected]
                     |                           |
                     v                           v
          +----------------------+     +--------------------+
          | Copy Original File   |     | Perform Surgical   |
          | Unchanged            |     | Sanitization       |
          +----------------------+     +--------------------+
                     |                           |
                     v                           v
          +----------------------+     +--------------------+
          | Verify SHA-256 Match |     | Reconstruct Output |
          | Input == Output      |     | File Container     |
          +----------------------+     +--------------------+
                     |                           |
                     v                           v
          +----------------------+     +--------------------+
          | Release Clean Output |     | Verify Integrity   |
          +----------------------+     | & Release Output   |
                                       +--------------------+
```

- When an input document contains **zero blocking findings**, DocShield performs a direct byte-for-byte copy to ensure that original timestamps, formatting, digital signatures, and cryptographic hashes (`SHA-256`) remain completely unmodified.
- When an input document contains **threats or policy violations**, DocShield performs surgical disarming and reconstruction. The SHA-256 of the output file will legitimately change as active content is eliminated.
