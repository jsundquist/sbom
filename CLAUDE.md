@AGENTS.md

## Claude Code specifics

- Follow the session start/end protocol in `AGENTS.md` without being asked. The `docs/progress.md` update is part of finishing a task.
- Use `/clear` between unrelated features; the files in `docs/` carry state across sessions, not conversation history.
- Prefer the `mattpocock-skills:tdd` skill for new logic in `src/server/`, `src/worker/` and `src/lib/`.

## Agent skills

### Issue tracker

Work is tracked in `docs/features.json` (no GitHub issues). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary, stored in an optional `labels` array on each feature. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
