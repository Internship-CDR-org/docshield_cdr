# DocShield Performance & Benchmarking Guidelines

## 1. Overview

DocShield is designed for high-throughput enterprise gateways, mail transfer agents (MTAs), and file ingestion pipelines. Performance is optimized by separating clean document fast-paths (zero transformation, byte-for-byte copy) from surgical reconstruction paths.

---

## 2. Processing Characteristics

### 2.1 Clean-Path Throughput
- Documents with no detected threats bypass the reconstruction and serialization pipelines.
- Processing involves fast in-memory parsing, threat inspection, and direct streaming copy with SHA-256 calculation.
- Typical processing latency for standard office documents (< 5 MB) is under **50–150 milliseconds**.

### 2.2 Reconstructed Threat-Bearing Throughput
- Threat-bearing documents undergo in-memory object decomposition, XML / COS tree sanitization, atomic file serialization, and post-reconstruction integrity re-reading.
- Typical latency for standard weaponized office documents is under **200–500 milliseconds**.

### 2.3 Legacy Office Conversion Throughput
- Legacy binary formats (`DOC`, `PPT`, `XLS`) require ephemeral LibreOffice conversion inside a supervised sandbox before modern OOXML CDR.
- Conversion overhead adds approximately **1.0–2.5 seconds** depending on system CPU and LibreOffice startup time.

---

## 3. Resource Allocation Guidelines

| Parameter | Default Value | Configuration Property | Description |
|---|---|---|---|
| **Max Package Size** | 256 MB | Internal constant | Maximum uncompressed total size for OOXML packages. |
| **Max Single Part** | 128 MB | Internal constant | Maximum single ZIP entry size. |
| **Max ZIP Entries** | 10,000 | Internal constant | Maximum allowed parts in an archive package. |
| **Recursive Depth** | 4 | `RecursiveOOXMLSanitizer` | Maximum nesting depth for embedded packages. |
| **Conversion Timeout** | 60 seconds | `-Ddocshield.libreoffice.timeout.seconds` | Maximum wall-clock time allowed for legacy conversion subprocess. |
| **Max Output Limit** | 200 MB | `-Ddocshield.libreoffice.max.output.bytes` | Maximum disk output allowed from LibreOffice subprocess. |
