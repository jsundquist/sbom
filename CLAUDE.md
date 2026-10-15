@AGENTS.md

## Claude Code specifics

- Follow the session start/end protocol in `AGENTS.md` without being asked. The `docs/progress.md` update is part of finishing a task.
- Use `/clear` between unrelated features; the files in `docs/` carry state across sessions, not conversation history.
- Prefer the `mattpocock-skills:tdd` skill for new logic in `src/server/`, `src/worker/` and `src/lib/`.
