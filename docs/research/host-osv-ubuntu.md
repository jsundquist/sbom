# Host CVEs via OSV for Ubuntu packages (W-007, parent W-006)

Question: can the dashboard show CVEs for the dpkg packages of an Ubuntu droplet running k3s, using the existing OSV/deps.dev worker?
Verdict: yes for CVEs, with changes. OSV covers Ubuntu well, but the match key is the **source package** plus an **Ubuntu release ecosystem**, and versions need **dpkg comparison**. deps.dev is useless for deb, so "latest" must come from apt.

Sources (all primary):
- [OSV schema](https://ossf.github.io/osv-schema/) (S1)
- [Ubuntu OSV data](https://documentation.ubuntu.com/security/security-updates/osv/) (S2)
- [OSV.dev data sources](https://google.github.io/osv.dev/data/) (S3)
- [OSV POST /v1/query](https://google.github.io/osv.dev/post-v1-query/) (S4)
- [osv.dev `purl_helpers.py`](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) (S5)
- [Syft `debian/package.go`](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/debian/package.go) and [`pkg/dpkg.go`](https://github.com/anchore/syft/blob/main/syft/pkg/dpkg.go) (S6)
- [Debian Policy, Version field](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version) (S7)
- [deps.dev API v3](https://docs.deps.dev/api/v3/) (S8)
- Sample record: [UBUNTU-CVE-2022-48620](https://osv.dev/vulnerability/UBUNTU-CVE-2022-48620) (S9)

## 1. What OSV exposes for Ubuntu/Debian

- **Ecosystem names (S1, S2).** `Ubuntu:YY.MM` with a mandatory `:LTS` suffix on LTS releases: `Ubuntu:22.04:LTS`, `Ubuntu:24.04:LTS`, `Ubuntu:25.04`. ESM fixes use `Ubuntu:Pro:18.04:LTS`. Pro services also appear as ecosystems (Realtime Kernel, FIPS, FIPS-updates, FIPS-preview). Debian is `Debian` with an optional `:<RELEASE>` suffix (`Debian:7`, `Debian:sid`).
- **Record types and IDs (S2).** `UBUNTU-CVE-YYYY-NNNN` (per CVE; `upstream` = the `CVE-...` id), `USN-...` (notices; `upstream` lists the `UBUNTU-CVE-*` ids it fixes), `LSN-...` (Livepatch; no source package, uses `ecosystem_specific.module_name_regex`). The bare `CVE-` prefix is reserved for the CVE Program feed. Debian ids are `DSA`/`DLA`/`DTSA` and `DEBIAN` (S1). Debian is a converted source, not a native one (S3).
- **`affected[].package.name` is the source package (S1, S2).** Ubuntu tracks vulnerabilities per source package. Binary names are in `ecosystem_specific.binaries[]` as `{binary_name, binary_version}` (S2, S9).
- **Ranges (S2).** `type` is always `ECOSYSTEM`, `introduced` is always `"0"`, `fixed` is the patched **source** version, and `versions` lists the affected source versions. OSV treats `introduced`/`fixed` as uninterpreted strings (S1), so comparing them is the client's job.
- **Unfixed CVEs stay in `affected` with no `fixed`** for tracker statuses needs-triage, needed, ignored, pending, deferred and in-progress. Only `released` has `fixed`. `DNE` and `not-affected` are omitted (S2). Our `fixedVersions()` returns `[]` for these, which is the correct "no fix yet".
- **Severity (S2, S9).** Only on `UBUNTU-CVE` records, not USNs. CVSS_V2/V3/V4 entries carry the vector. A separate `Ubuntu` priority (critical/high/medium/low/negligible) is also present. USNs have no severity, so show the linked `UBUNTU-CVE` severity.
- **Each `affected` entry has a purl (S9):** `pkg:deb/ubuntu/<source>?arch=source&distro=<codename>` (for example `distro=jammy`).
- **Not verified:** whether a query with ecosystem `Ubuntu` and no release matches the suffixed `Ubuntu:22.04:LTS` records. The query docs (S4) do not say. Test against the live API before relying on it. S1 only says the suffix is optional for Debian.

## 2. How Syft emits dpkg purls

From S6 (`packageURL`):
- Format: `pkg:deb/<distro.ID>/<Package>@<binary Version>?arch=<Architecture>&upstream=<Source>@<SourceVersion>&distro=<distro>`.
- Namespace is the os-release `ID`, so `ubuntu` on Ubuntu. Syft returns an empty purl if the distro is missing, or if the distro is neither `debian` nor has `debian` in `ID_LIKE`. If the scan has no distro (for example scanning a bare directory without os-release), there is **no purl at all**.
- Name and version are the **binary** package's (`Package`, `Version`). `upstream` is present only when dpkg has a `Source:` field, and carries `source@sourceVersion`. `SourceVersion` can differ from the binary version after binNMU (`pkg/dpkg.go`).
- The `distro=` qualifier value comes from `pkg.PURLQualifiers(qualifiers, distro)`, whose body I did not read. Treat the exact value (for example `ubuntu-22.04` vs a codename) as unverified. Capture a real Syft SBOM from the droplet to confirm.
- OSV's purl parser (S5) maps `deb`+`ubuntu` to `Ubuntu` and `deb`+`debian` to `Debian`. It **reads only name, version, type, namespace and subpath, and ignores qualifiers** (so `distro` and `upstream`). It never produces a release-suffixed ecosystem. An unknown deb namespace returns None.

Consequence: the current query `{package:{purl: "pkg:deb/ubuntu/<binary>"}, version}` (from `toQuery` in `src/worker/osv.ts`) sends the **binary** name and binary version, with no release. Ubuntu records are keyed by the **source** name, so any package whose binary name differs from its source (`libssl3` vs `openssl`, `libuev3` vs `libuev`) would probably return nothing. That would look like a clean host when it is not. This follows from S2 plus S5, but I did not run a live query.

## 3. Version comparison

- dpkg format (S7): `[epoch:]upstream_version[-debian_revision]`, split at the **last** hyphen. A missing epoch is 0 and a missing revision is `0`. Compare epoch numerically, then upstream, then revision. Each of those is compared by alternating non-digit and digit runs. Non-digit runs compare in ASCII order, except that letters sort before non-letters and `~` sorts before everything, including the end of the string (`1.0~beta1 < 1.0`). Digit runs compare numerically.
- `src/lib/version.ts` is wrong for this:
  - `parseVersion` strips everything from the first `+` (so `1.2+dfsg` collapses to `1.2`, and `+esm1`-style suffixes are lost).
  - There is no epoch handling: `1:2.0` parses as release `[1]` with qualifier `2`, `0`, so epoch ordering breaks.
  - `~` is treated as a plain separator, so `1.0~rc1` is not below `1.0`.
  - Letters are tokenized and `PRE_RE` guesses prereleases, which does not apply to dpkg.
  - `updateType` uses major/minor/patch on release segments, which has no meaning for `2.37.2-4ubuntu3.6`.
- Required: a `compareDebVersions` implementing S7 exactly (about 40 lines, easy to unit-test with the policy examples), selected by purl type (`deb`) in `compareVersions`/`maxVersion`/`fixedVersions`. The ecosystem is already known from the package row. `fixedVersions()` sorts with `compareVersions`, so it must dispatch too.
- Version-match caveat: OSV `versions` and `fixed` hold **source** versions. Compare against the `upstream` qualifier's source version, falling back to the binary version. Do not compare the binary version when a binNMU (`+b1`) differs.

## 4. deps.dev for deb

deps.dev API v3 supports only GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI and NUGET (S8). Debian and Ubuntu are not supported, and `depsDevSystem('deb')` is already `null` (`src/lib/ecosystems.ts`), so `latestVersion` returns null with no code change. Confirmed useless for deb.

So "latest version" must come from the host. Options: (a) ingest `apt list --upgradable` / `apt-get -s upgrade` output (candidate version per binary package, per the configured archives, including `-security`), sent with the host's SBOM; (b) read per-release Packages indexes from the archive (heavier, a new external source). Option (a) is simpler, correct for what that host can actually install, and needs no new egress. Candidates are only as fresh as the last `apt update` on the host. I did not read apt docs in this pass; (a) is a design suggestion, not a researched claim.

## 5. What would have to change (no code changed in this ticket)

1. `src/lib/ecosystems.ts`: `deb` is already in `OSV_TYPES`, so rows are already queued. Add an `osvEcosystem(...)` helper mapping `deb/ubuntu` plus release to `Ubuntu:22.04:LTS`. The release should come from host metadata (os-release `VERSION_ID`, plus an LTS flag), not from parsing the `distro` qualifier. It needs storing (new column, or on the host/application row).
2. `src/worker/osv.ts` `toQuery`: for deb, query `{package:{name:<source>, ecosystem:"Ubuntu:<rel>[:LTS]"}, version:<source version>}` instead of the purl form. The source and its version come from the purl `upstream` qualifier, falling back to the binary name and version. `package.purl` must be omitted when name and ecosystem are used (S4). Also store the `upstream` qualifier, since `basePurl` drops qualifiers.
3. `fixedVersions()`: matching uses `p.purl` (no qualifiers) or the normalized name. For Ubuntu the record's purl is a source purl with a different name from the installed binary, so use the resolved source name. Filter `affected` by the host's ecosystem so a fix for `noble` is not shown for `jammy`. A `versions` entry with no `fixed` means "unfixed", not an error.
4. `src/lib/version.ts`: add a dpkg comparator and dispatch on type (section 3). Disable major/minor/patch classification for deb.
5. `osvSeverity`: USN records have no severity. Prefer the linked `UBUNTU-CVE` record (via `upstream`), and use the `Ubuntu` priority label as fallback (needs wiring, since the code currently reads `severity` from `database_specific`/`ecosystem_specific`).
6. `src/worker/depsdev.ts`: nothing. Latest version comes from an apt-upgradable ingest path (new data on the host's packages, written through `src/server/ingest.ts` per the layering rules).
7. Dedup/display: one vulnerability appears as `UBUNTU-CVE-*`, `USN-*` and `CVE-*` (via `upstream`). Group by `upstream` in the UI to avoid triple counting.
8. Syft must run with the distro detected (os-release readable, for example scanning `/` on the host), otherwise no deb purl is emitted (S6).

## Open items to verify before building

- Live OSV query: does `{name, ecosystem:"Ubuntu"}` (no release) match suffixed ecosystems, and does a binary-name purl return anything?
- Exact `distro=` value Syft emits on Ubuntu 22.04/24.04 (read `pkg.PURLQualifiers` or capture a real SBOM).
- apt candidate data format and how to ship it to the dashboard (separate ticket).
