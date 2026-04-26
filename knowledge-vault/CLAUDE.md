---
title: Vault Conventions
updated: 2026-04-26
status: active
---

# Knowledge Vault Conventions

This vault tracks the operational truth of the Email Security Gateway project.

## Purpose
- Keep implementation reality synchronized with project documentation.
- Preserve a compact hot cache for fast context restoration.
- Record verified system behavior and validation outcomes.

## File Roles
- `wiki/hot.md`: short, current working context
- `wiki/overview.md`: architecture and behavior snapshot
- `wiki/log.md`: chronological change log
- `wiki/index.md`: catalog and entry points
- `wiki/concepts/*`: deep-dive technical notes

## Authoring Rules
- Use frontmatter on wiki pages.
- Use wikilinks for internal references.
- Prefer short, factual notes over speculative claims.
- Update `wiki/hot.md` and `wiki/log.md` after significant operations.

## Source of Truth Policy
- Runtime code and passing tests are the authority.
- If docs and implementation conflict, document the delta and update docs.
- Preserve historical notes in `wiki/log.md` but keep `wiki/hot.md` current.

