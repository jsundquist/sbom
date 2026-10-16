# Issue tracker: docs/features.json

Tickets live as entries in the `features` array of `docs/features.json`. Edit the file directly; there is no CLI and no GitHub
Issues. Keep it valid JSON (`python3 -c "import json;json.load(open('docs/features.json'))"`). The file is excluded from Prettier.

## Conventions

- **Create a ticket**: append an entry with `id` (epic letter + number, e.g. `A-009`; unique), `title`, `epic`, `size` (S/M/L),
  `priority` (lower runs first), `status: "todo"`, `depends_on` (ids), `acceptance` (list), `evidence: ""`, optional `notes`, `labels`.
- **Read a ticket**: find the entry by `id`; its `notes` are the comments.
- **List tickets**: filter by `status` / `labels` / `epic`. The next ticket is the lowest-`priority` `todo` whose `depends_on` are all `done`.
- **Comment**: append a short dated sentence to `notes`. Session-level narrative goes in `docs/progress.md`.
- **Apply / remove labels**: edit the `labels` array.
- **Close**: set `status` to `done` and fill `evidence` with the commands run and results (see `docs/WORKFLOW.md#definition-of-done`),
  or `status: "superseded"` plus `superseded_by`.

## PRs as a request surface

**PRs as a request surface: no.**

## When a skill says "publish to the issue tracker"

Append a ticket entry to `docs/features.json` and commit it.

## When a skill says "fetch the relevant ticket"

Read the entry with that `id` from `docs/features.json`.

## Wayfinding operations

- **Map**: an entry labelled `wayfinder:map` holding Notes / Decisions-so-far / Fog in `notes`.
- **Child ticket**: an entry with `parent: "<map id>"` and label `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`).
- **Blocking**: `depends_on`; a ticket is unblocked when every dependency is `done`.
- **Frontier**: the map's open children with all dependencies `done` and no `assignee`; first by `priority` wins.
- **Claim**: set `assignee` and `status: "in_progress"`.
- **Resolve**: write the answer into `notes`, set `status: "done"`, and append a pointer to the map's Decisions-so-far.
