# PPTX Embedded Content CDR Policy

| Situation | Action |
|---|---|
| Normal embedded object | Inspect; preserve if no blocking finding |
| Clean embedded OOXML | Reconstruct in memory and preserve |
| Embedded OOXML with sanitizable threat | Sanitize nested document, re-analyze, reconstruct and preserve |
| Embedded OOXML remains unsafe after sanitization | Remove containing embedded package |
| Embedded OOXML cannot be parsed/reconstructed | Remove containing embedded package |
| Recursive depth/resource limit reached | Blocking uninspectable finding; remove containing boundary |
| Clean OLE compound object | Preserve |
| OLE contains unsafe nested OOXML | Remove containing OLE object |

The policy is fail-closed for uninspectable content and fail-preserving for content that can be safely sanitized.
