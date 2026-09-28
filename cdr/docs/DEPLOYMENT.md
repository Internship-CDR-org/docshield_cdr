# DocShield Deployment & Operations Guide

## 1. System Requirements

### Hardware Requirements
- **CPU**: 2 cores minimum (4+ cores recommended for high-concurrency ingestion).
- **RAM**: 2 GB minimum (4 GB+ recommended).
- **Disk**: High-speed NVMe or SSD storage for staging temporary files and quarantine records.

### Software Requirements
- **Java Runtime**: OpenJDK 21 LTS or compatible JRE 21+.
- **Operating System**: Linux (Ubuntu 22.04 LTS+, Debian 12+, RHEL 9+ recommended for production; Windows 10/11 supported for development).
- **External Dependencies**:
  - `libreoffice` (required for legacy `.doc`, `.ppt`, `.xls` conversion).
  - `bubblewrap` / `bwrap` (recommended on Linux for kernel-level namespace sandboxing).

---

## 2. Installation & Build

### Building from Source
```bash
git clone https://github.com/Pardhu-26/docshield_cdr.git
cd docshield_cdr/cdr
mvn clean package -DskipTests
```

The generated executable JAR will be located in:
`target/cdr-1.0-SNAPSHOT.jar`

---

## 3. Command Line Interface (CLI)

### Basic Usage
```bash
java -jar target/cdr-1.0-SNAPSHOT.jar <input-file> <output-file>
```

### Example: Processing a Document
```bash
java -jar target/cdr-1.0-SNAPSHOT.jar /data/incoming/invoice.docx /data/clean/invoice.docx
```

### System Configuration Properties

DocShield supports runtime configuration via JVM system properties:

| Property | Default | Description |
|---|---|---|
| `-Ddocshield.libreoffice.command` | `libreoffice` | Path to the LibreOffice executable (`soffice` / `libreoffice`). |
| `-Ddocshield.libreoffice.timeout.seconds` | `60` | Timeout in seconds for legacy document conversions. |
| `-Ddocshield.libreoffice.max.output.bytes` | `209715200` (200MB) | Max bytes allowed from conversion output. |
| `-Ddocshield.sandbox.bwrap.disable` | `false` | Set to `true` to force disabling Bubblewrap sandboxing. |

---

## 4. Exit Codes for Gateway Integration

DocShield is designed for seamless integration into email gateways and file pipelines:

- **Exit Code 0**: Success. Output file is valid and safe to release.
- **Exit Code 1**: Operator or argument error (invalid CLI arguments, unreadable path, unwritable destination).
- **Exit Code 2**: Security or processing failure. Original file has been quarantined; do not release output.
