# Research: how to get a prod-only SBOM from Syft

Ticket: J-001. Feeds J-002 (store component scope from the Action). Researched 2026-11-17. No application code changed.

## Answer

Syft cannot produce a prod-only SBOM from a pnpm project, and it cannot mark dev packages, on the version measured (1.57.1). Recommendation: **a lockfile-derived runtime list, applied in the Action as CycloneDX `scope` on the document before upload** (a variant of option c; not a header, see below). For images, the image is already the runtime set and no marking is needed.

| Option | Verdict |
|---|---|
| (a) second scan, difference is dev | Does not work for a checkout (pnpm keeps the lockfile, which Syft reads). Works for an image only if CI builds a dev-including image as well. |
| (b) Syft config | `javascript.include-dev-dependencies` exists but has no effect on a pnpm checkout or image. Rejected. |
| (c) lockfile-derived list | Works; exact on this repo. Recommended, sent inside the document as `scope`. |

## Measurements

Syft 1.57.1 (Homebrew, darwin/arm64), pnpm 11.21.0, Node 24.18.0 (repo wants 26+; not needed for these commands), Docker 29.9.3. Scans of `git archive HEAD` copies of main at 28c0157 (what CI sees: no `node_modules`), in a scratch directory. All Syft runs used `-o cyclonedx-json`.

### This repo (checkout)

| Scan | Command | Components | npm packages (unique purls) |
|---|---|---|---|
| Full | `syft dir:.` | 655 (650 library, 5 file) | 628 (+21 GitHub Actions purls) |
| After `pnpm install --prod --frozen-lockfile` | same `syft dir:.` | 655 | 628 |
| Prod install with `pnpm-lock.yaml` deleted | `syft dir:.` | 26 (all file entries) | 0 |
| Syft with `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=false` (also via `-c` file) | `syft dir:.` | 655 | 628 |
| pnpm, lockfile only, all | `pnpm sbom --sbom-format cyclonedx --lockfile-only` | 628 | 628 |
| pnpm, prod | `... --lockfile-only --prod` | 266 | 266 |
| pnpm, dev | `... --lockfile-only --dev` | 369 | 369 |

- The ticket's "1,975 components" did not reproduce: a fresh checkout gives 655; a worktree with `node_modules` installed gives 679 (the extra are workflow and binary files inside `node_modules`). 1,975 is likely a scan that included other directories (for example agent worktrees).
- Syft's 628 npm purls equal pnpm's 628 purls exactly (both use `%40` for `@`), so matching by purl is safe.
- Prod 266 and dev 369 overlap in 80 packages (reachable from both), so dev-only is 289. A further 73 are per-platform optional binaries of dev tools (esbuild, lightningcss, rolldown) that neither `--prod` nor `--dev` lists. Everything not in the prod set is 362 packages; `vitest`, `typescript` and `eslint` are in it.
- Syft emits no `scope` anywhere in the document (0 of 655), and its pnpm entries carry only `integrity` and `dependencies` metadata, no dev flag. The ticket's claim is confirmed for 1.57.1.
- `pnpm install --prod` does not help because Syft's lockfile cataloger reads `pnpm-lock.yaml` (`foundBy: javascript-lock-cataloger`), which still lists devDependencies. Deleting the lockfile leaves nothing, because Syft finds no npm packages under pnpm's symlinked `node_modules/.pnpm` layout.
- Dev flag in config: `syft config` lists `javascript.include-dev-dependencies` (env `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES`) and the scan descriptor echoes `include-dev-dependencies: false`, yet the count is unchanged. Source: the field is declared in `syft/pkg/cataloger/javascript/config.go` ("whether development dependencies should be included ... in addition to production dependencies", default false) and is passed to the pnpm-lock adapter in `cataloger.go`, but dev packages are listed anyway, so the pnpm-lock parser does not honour it on this version.

### One container image (this repo's own, `docker build` of `Dockerfile`)

Three stages of the repo's Dockerfile, scanned with `syft docker:<tag> -o cyclonedx-json`:

| Image | Command | Components | library | npm purls | dev packages present |
|---|---|---|---|---|---|
| `web` (shipped, Next standalone) | `docker build --target web -t sbom-web:j001 .` | 1,460 | 97 | 82 | 0 |
| `worker` (shipped, after `pnpm prune --prod`) | `--target worker` | 1,870 | 302 | 287 | 0 |
| `build` stage (has devDependencies) | `--target build` | 5,121 | 1,108 | 869 | 293 |

- "Dev packages present" means the npm purl is in the lockfile but not in the `pnpm sbom --prod` set. `vitest 5.1.0`, `typescript 6.0.3` and `eslint 9.39.5` appear in the build stage and not in web.
- The shipped images are already prod-only because the Dockerfile builds them that way (standalone tracing, `pnpm prune --prod`). Most `file` components (1,361 of 1,460 in web) are not packages.
- 55 npm purls in web are not in the lockfile (Next's vendored `next/dist/compiled/*`, mostly without versions), so a lockfile list cannot classify them. They would stay `unknown`.
- `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=false` on the build image still gave 5,121.
- Option (a) works for images (full minus prod = dev) only when CI also builds and scans a dev-including target. This repo does not ship one; the `build` stage was built just to measure.

## Primary sources

- CycloneDX 1.6 `component.scope`: https://cyclonedx.org/docs/1.6/json/ . Values are `required` (required for runtime, the default), `optional` (not installed or reachable) and `excluded` ("document component usage for test and other non-runtime purposes ... not reachable within a call graph at runtime"). There is no `dev` value; `excluded` is the closest and also covers test-only components.
- pnpm `sbom`: https://pnpm.io/cli/sbom . `--prod` ("Only include `dependencies` and `optionalDependencies`"), `--dev`, `--lockfile-only`, CycloneDX 1.5 to 1.7 and SPDX 2.3. The page does not say which pnpm version added the command; verified only on 11.21.0.
- Syft: https://github.com/anchore/syft (README covers JavaScript support, nothing on dev scope); config keys from `syft config` on 1.57.1; source `https://raw.githubusercontent.com/anchore/syft/main/syft/pkg/cataloger/javascript/config.go` and `cataloger.go`.
- Not read: Syft release notes. The no-scope claim was checked by running the binary instead, which is stronger for the version in question.

## Trade-offs against this project

Constraints: the Action (`action.yml`) generates the SBOM through `anchore/sbom-action` v0.24.3 and uploads with `curl --data-binary`; ADR 0004 says columns arrive as upload metadata from CI (query or `X-Sbom-*` headers); all input is Zod-validated; uploads without scope must still ingest as `unknown` (J-002).

- (a) Second scan: doubles CI time, needs a dev-including install or image to diff against, and for a pnpm checkout there is no prod scan to diff with (measured). Rejected for checkouts.
- (b) Syft config: no effect on pnpm (measured), and a config cannot mark dev, only drop it. Dropping dev would also hide dev vulnerabilities from the dashboard, which J-002 does not want ("No change to ranking"). Rejected.
- (c) Lockfile list: needs the package manager on the runner. `pnpm sbom` needs pnpm (the Action does not install it today; `corepack` or `npx pnpm@11` can supply it), and it is pnpm-specific; npm has `npm sbom --omit=dev`, other ecosystems have nothing equivalent. Syft's purls match, so the join is exact.
  - Do not send the list as a header or query: the 266 prod purls are 8.3 KB and the 362 non-prod purls 12 KB (measured), at or over typical header limits (about 8 KB) and growing with the lockfile. Put it in the document instead: set CycloneDX `scope: "excluded"` on every component not in the prod purl set, `required` on the rest, then upload the same file. The server already parses CycloneDX through Zod, so J-002 adds `scope` to the schema and maps `excluded` to `dev`, `required` to `runtime`, absent to `unknown`. This keeps ADR 0004's rule that CI decides and the server only stores, with no new header.
  - Failure mode: if the pnpm step fails or the ecosystem is not pnpm, upload unmodified and everything stays `unknown`, never wrongly `runtime`.

## Recommendation for J-002

1. Action: for pnpm checkouts, run `pnpm sbom --sbom-format cyclonedx --lockfile-only --prod`, collect the purls, and stamp `scope` into the Syft CycloneDX file (a small `jq` step) before upload. Treat packages in neither list (per-platform optional binaries) as `excluded`, and check that a package in both prod and dev stays `required`.
2. Images: leave components unscoped (`unknown`) or, if J-002 prefers, `runtime` by declaration, since a shipped image has no dev tools by construction. A build-stage scan is the only way to see dev packages in an image.
3. Server: accept CycloneDX `scope` (`required`, `optional`, `excluded`) and the string `unknown`; the migration default stays `unknown`.
4. Re-check on the Syft version `anchore/sbom-action` v0.24.3 downloads: it was not run here, only 1.57.1 locally.

## Not measured

- The Action itself in a real workflow (its bundled Syft version, whether `pnpm` can run on the runner).
- Other package managers (npm, yarn) and ecosystems.
- The stamping step; it is a design, not run code.
