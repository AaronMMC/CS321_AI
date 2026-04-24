# Email Security Gateway: Agent Instructions

This repository integrates claude-obsidian practices to build a persistent, compounding knowledge base for email security threat detection and analysis. It works with any AI coding agent that supports the Agent Skills standard, including OpenCode, Codex CLI, and similar.

## Skills Discovery

All skills live in `.opencode/skills/<name>/SKILL.md`. OpenCode / Codex CLI / other Agent Skills compatible agents will auto-discover them when properly configured.

## Available Skills

| Skill | Trigger phrases |
|---|---|
| `email-analysis` | analyze email, check threat, scan message, assess email risk |
| `model-training` | train model, retrain, optimize model, improve accuracy |
| `system-monitoring` | monitor system, check performance, system health, analyze metrics |
| `dashboard-management` | manage dashboard, update ui, configure alerts, visualization |

## Key Conventions

- **Knowledge Vault Root**: the directory containing `knowledge-vault/wiki/` and `knowledge-vault/.raw/`
- **Hot Cache**: `knowledge-vault/wiki/hot.md` (read at session start, updated at session end)
- **Source Documents**: `knowledge-vault/.raw/` (immutable: agents never modify these)
- **Generated Knowledge**: `knowledge-vault/wiki/` (agent-owned, links to sources via wikilinks)
- **Manifest**: `knowledge-vault/.raw/.manifest.json` tracks ingested sources (delta tracking)

## Bootstrap

When working with this project:

1. Read this file (`AGENTS.md`) for context on available skills
2. If `knowledge-vault/wiki/hot.md` exists, read it silently to restore recent context
3. Route commands to appropriate skills based on trigger phrases
4. Maintain hot cache after every significant operation
5. Always use wikilinks and frontmatter in knowledge vault entries

## Reference

- claude-obsidian plugin: https://github.com/AgriciDaniel/claude-obsidian
- Pattern source: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
- Cross-reference: https://github.com/kepano/obsidian-skills (authoritative Obsidian-specific skills)