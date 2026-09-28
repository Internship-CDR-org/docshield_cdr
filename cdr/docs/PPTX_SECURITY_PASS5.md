# PPTX Security Pass 5 — Recursive Embedded CDR

## Purpose

PPTX embedded OOXML packages are now treated as recursive CDR boundaries instead of opaque binaries.

## Behavior

1. Detect an embedded OOXML package.
2. Parse it in memory.
3. Run the same common OOXML security policy, with PPTX-specific analysis when the nested package is PPTX.
4. Recursively process nested embedded packages.
5. Sanitize the nested package.
6. Re-analyze it.
7. If clean, reconstruct the nested package in memory and put the sanitized bytes back into the original embedded part.
8. If it remains unsafe or cannot be inspected/reconstructed safely, remove the containing embedded package and its package references.

## Resource safeguards

The default limits are:

- Maximum recursive depth: 4
- Maximum embedded package bytes: 64 MiB
- Maximum ZIP entries per nested package: 10,000
- Maximum nested packages inspected per outer package: 256

These are resource/security limits, not format capabilities. They prevent attacker-controlled recursion and decompression/resource exhaustion. Reaching a limit is a blocking `SUSPICIOUS_ARCHIVE` finding; content is never silently trusted.

The limits are constructor-configurable for controlled deployments/tests.

## OLE boundary

OLE Compound Files can contain OOXML Package streams. Those streams are inspected for nested OOXML threats. The current pass does not rewrite arbitrary OLE compound files in place. If a nested OOXML threat is found inside an OLE container, the containing OLE part is removed rather than performing unsafe byte-level surgery. Clean OLE objects remain preserved.
