# SBOM Dashboard

Dashboard for SBOMs and their vulnerabilities, with a separate worker that enriches packages.

## Language

**Owner**:
The single GitHub account, identified by its numeric user id, that may view the dashboard. Everyone else can sign in with GitHub but is shown nothing.
_Avoid_: Admin, user, viewer

**Upload token**:
A bearer secret the GitHub Action uses to upload an SBOM. It is separate from signing in and grants no read access.
_Avoid_: API key

**Project**:
One thing that uploads SBOMs and is tracked on its own: a unique name, a Kind, optionally a Repository. A monorepo with five services is five Projects. The UI and API use this word for the general concept.
_Avoid_: Application (that is one Kind, not the general term), deployable, component

**Kind**:
What a Project is: `application`, `library`, `image` or `host`. Set by the uploader on every upload, defaults to `application`, and is `image` when the Action scans an image.
_Avoid_: Type (taken by component type), category

**Repository**:
The normalised source location of a Project, `github.com/owner/repo`, stored as a column on the Project, not as its own table. Several Projects can share one.
_Avoid_: Repo URL, remote

**Tag**:
A free-form label the uploader attaches to a Project (team, tier, "internet-facing"). Replaced on every upload; the dashboard never edits them.
_Avoid_: Group, label (label means a triage label in `docs/features.json`)

**Read token**:
A bearer secret from `READ_TOKENS` that lets a script or the MCP server call `GET /api/v1/*` and `/metrics`. It never opens pages and cannot write.
_Avoid_: API key

**Admin token**:
A bearer secret from `ADMIN_TOKENS` that authorises deleting a Project. Separate from the Upload token, which can no longer delete.
_Avoid_: Delete key

**Stale SBOM**:
A Project whose latest SBOM was uploaded more than `STALE_AFTER_DAYS` ago. A flag, not an error: an abandoned pipeline must not look healthy.
_Avoid_: Old, outdated (outdated means a package behind its latest version)

**Scope**:
Whether a component is needed at runtime: `runtime`, `dev` or `unknown`. Only labels and filters; it does not change vulnerability ranking.
_Avoid_: Dependency type

**Upgrade**:
A remediation action: raise one package from a version in use to a target version, with the number of vulnerabilities it clears. Ranked by the risk it retires, not by CVE.
_Avoid_: Fix, patch

**Rollup**:
Per-Project counts the worker precomputes so cross-Project views do not load every component.
_Avoid_: Cache, summary
