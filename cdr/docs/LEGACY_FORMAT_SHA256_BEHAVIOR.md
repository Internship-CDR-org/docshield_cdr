# Legacy Office SHA-256 and Clean-Copy Behavior

## Purpose

Native OOXML inputs (`DOCX`, `PPTX`, `XLSX`) can be copied byte-for-byte when the full security analysis reports no blocking findings. This preserves the input SHA-256.

Legacy binary Office inputs (`DOC`, `PPT`, `XLS`) are different: they must first pass through the isolated LibreOffice conversion to `DOCX`, `PPTX`, or `XLSX`. The converted artifact is necessarily a new file and therefore is not expected to retain the original legacy file's SHA-256.

## Correct result semantics

- Native OOXML clean input: `originalCopied=true`, `reconstructionSuccessful=false`, identical input/output SHA-256.
- Legacy input whose converted OOXML is clean: the legacy adapter treats the conversion result as a successful overall output (`reconstructionSuccessful=true`, `originalCopied=false`).
- Legacy input with a detected threat: conversion plus OOXML CDR sanitization/reconstruction must produce a usable, integrity-validated output with no remaining blocking findings.
- A missing output remains a failure; clean-copy semantics must never turn an absent output into success.
