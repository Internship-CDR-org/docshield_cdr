# PPTX Model

PPTX is an Office Open XML package and therefore uses the common `model.ooxml` package model.

The `model.pptx` package contains only PowerPoint-specific semantic models that are not part of the physical OPC package graph:

- `PPTXLayout`
- `PPTXLayoutElement`
- `PPTXTheme`

Physical package parts, relationships, and content types are represented by:

- `model.ooxml.OOXMLPackage`
- `model.ooxml.OOXMLPart`
- `model.ooxml.OOXMLRelationship`

This prevents DOCX, XLSX, and PPTX from maintaining separate physical package models.
