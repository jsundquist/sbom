# Coding standards: judgement calls

For reviewers (and implementers). Only things a linter cannot catch; mechanical rules live in ESLint, Prettier and CI.
Layering and workflow are in `AGENTS.md`.

- **Fail closed.** A value that gates access (secret, token, allow-list) must deny when missing or weak. Validate minimum strength in Zod; "non-empty" is not "configured".
- **One mapping per domain state.** One function turns a domain state (for example an auth outcome) into a response. Proxy, route and page call it; none re-derive it.
- **No duplicated literals.** Denial codes, statuses and user-facing messages are defined once and imported, never retyped across proxy and server.
- **Reject, do not repair.** Invalid external input is a visible error (400, a log), not silently truncated or defaulted; a typo in CI should show up.
- **Say what is not verified.** A claim of done names what was run; untested paths go in `docs/progress.md` as "Not done".
