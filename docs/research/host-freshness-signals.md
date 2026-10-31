# Host and k3s freshness signals (W-008, parent W-006)

Question: which facts can a collector on an Ubuntu droplet read to answer "is this server up to date", and where does the "latest" reference come from?

Researched 2026-10-31. Sources are first-party (Ubuntu docs and manpages, k3s docs, endoflife.date API, update.k3s.io). Live API responses were fetched directly on that date; sample values below will drift. Items not backed by a fetched primary page are marked **UNVERIFIED**.

## Architecture fit

The dashboard receives pushed data only, and external HTTP lives in `src/worker/` behind `FetchFn`. So:

- **Collector (host)** reads local facts and pushes them. It makes no calls to public references.
- **Worker (reference)** fetches "latest" and EOL data from public APIs and joins it to pushed facts. Comparing "node runs v1.33.9" against "latest v1.33.13" happens server-side, not on the host.

## Summary table

| Fact | Where read | Source of truth |
|---|---|---|
| Pending upgrades, count and names | host | `apt-get -s upgrade` |
| Security vs other split | host | origin suite on `Inst` lines (`-security`, `esm-*`) |
| ESM / Pro state, ESM-provided updates | host | `pro status`, `pro security-status` |
| Reboot required, and which packages | host | `/var/run/reboot-required`, `.pkgs` |
| Running vs installed kernel | host | `uname -r` vs installed `linux-image-*` (UNVERIFIED, see below) |
| unattended-upgrades enabled and last run | host | `/etc/apt/apt.conf.d/20auto-upgrades`, `/var/log/unattended-upgrades/` |
| Ubuntu release (version, codename) | host | `/etc/os-release` |
| Ubuntu release EOL, ESM end | worker | endoflife.date API |
| k3s node version | host | `k3s --version` or the Kubernetes node `kubeletVersion` (UNVERIFIED) |
| k3s latest patch in node's minor | worker | `update.k3s.io` channel `vX.Y` |
| k3s minor EOL | worker | endoflife.date `kubernetes` product (inference, see below) |

## 1. Pending apt upgrades (host)

- `apt-get -s upgrade` (`-s`, `--simulate`) "perform[s] a simulation of events that would occur based on the current system state". It changes nothing, disables locking, and non-root users can run it. A non-root user may not read all apt configuration, so run the collector as root for faithful results. Source: [apt-get(8)](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html).
- Output: one line per dpkg operation; `Inst` lines are unpacks. Same man page. The `Inst` line also carries the candidate version and origin in parentheses, for example `(1.2-3ubuntu1 Ubuntu:24.04/noble-security [amd64])`. The origin text is how security is split from other (see below). **UNVERIFIED** against a primary page in this session: the parenthesised origin format. Confirm on a real host before building a parser.
- `upgrade` never removes packages and holds back anything that would need another package's install state changed; those stay at the current version ([apt-get(8)](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html)). Held-back packages are not counted as `Inst`, so also read the "kept back" count. Decide whether "up to date" should use `dist-upgrade -s`, which also resolves dependency changes.
- Phased updates: apt may keep back a package that is rolling out to a percentage of machines, and "security updates are not phased". The client decides from machine ID, package name and version. Source: [About apt upgrade and phased updates](https://ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/). Consequence: a non-security "kept back" package can be benign; do not flag it as stale.
- `apt list --upgradable` lists packages with a newer candidate. The `apt` man page warns the CLI "may change behavior between versions" and recommends `apt-get` / `apt-cache` for scripts ([apt(8)](https://manpages.ubuntu.com/manpages/noble/man8/apt.8.html)). Prefer `apt-get -s` for the collector.
- Freshness of the data itself: both commands compare against the local package lists, which are only as new as the last `apt update` (`APT::Periodic::Update-Package-Lists`, default daily, see section 4). The collector should push the mtime of `/var/lib/apt/periodic/update-success-stamp` or `/var/lib/apt/lists/` (**UNVERIFIED** path; the Ubuntu automatic-updates page does not mention stamp files) so the dashboard can show "list age". Do not run `apt-get update` from the collector without an explicit decision, since it mutates host state.

### Security vs other

- Security updates come from the `<codename>-security` suite; ESM from the ESM archive. unattended-upgrades' default `Allowed-Origins` lists `${distro_id}:${distro_codename}-security` plus the ESM entries, with `-updates`, `-proposed`, `-backports` commented out ([Automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)).
- Pro client docs name an update provider of `esm-infra`, `esm-apps` or `standard-security` in the `u.pro.packages.updates.v1` schema, a ready-made classification ([Ubuntu Pro Client docs](https://documentation.ubuntu.com/pro-client/en/docs/references/commands/)).
- Practical rule: classify each `Inst` line by origin suite: contains `-security` or `esm` is security; anything else is other. A package can be in both `-security` and `-updates`; count it as security.

## 2. ESM / Ubuntu Pro (host)

- `pro security-status --format json` summarises installed packages by origin (main, restricted, universe, multiverse, esm-infra, esm-apps). Flags: `--thirdparty`, `--unavailable`, `--esm-infra`, `--esm-apps`. Source: [pro CLI reference](https://documentation.ubuntu.com/pro-client/en/docs/references/commands/).
- `sudo pro status --format=json` gives service state; the docs advise treating any status other than `enabled` as not enabled. The JSON output of `pro status` is described as experimental, so pin field names against the installed client version (same source).
- Why it matters: on an LTS past standard support, security fixes for `main` come only through esm-infra. A host without Pro attached shows no ESM updates in apt, so "0 pending security" can be a false all-clear. Collect both the Pro attach state and `pro security-status` counts of packages that have ESM updates available but are not enabled.
- Pro is not attached by default on a droplet, so the collector must tolerate `pro` being absent or unattached.

## 3. Reboot required and kernel (host)

- `/var/run/reboot-required` is the flag; packages list themselves in `reboot-required.pkgs` (maintainer scripts touch the first and append to the second). Sources: [Ubuntu wiki UpdateNotifier](https://wiki.ubuntu.com/UpdateNotifier), [Ubuntu deb maintainer scripts guide](https://discourse.ubuntu.com/t/ubuntu-deb-package-maintainer-scripts-hooks-triggers-tips-tricks/36174). `/var/run` is a symlink to `/run` on current Ubuntu, so the two paths in sources are equivalent (**UNVERIFIED** in this session).
- unattended-upgrades logs the flag as `/var/run/reboot-required` and can reboot on its own: `Automatic-Reboot` defaults to `"false"`; `Automatic-Reboot-WithUsers` `"true"`; `Automatic-Reboot-Time` `"now"` ([Automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)). With auto-reboot off, a security kernel can sit installed but not running indefinitely, so push the file's mtime (reboot-pending age), not only a boolean.
- Ubuntu also exposes `pro system reboot-required` as an equivalent check ([Ubuntu cloud updates guide](https://ubuntu.com/blog/ubuntu-updates-best-practices-for-updating-your-instance)). Its output values were not verified.
- **UNVERIFIED (no primary page fetched):** running kernel is `uname -r`; the newest installed kernel is the highest version among `/boot/vmlinuz-*` or installed `linux-image-*` packages. If they differ, the running kernel is stale even when no flag file exists (for example if the flag was cleared or lost). Compare with a version-aware sort (`dpkg --compare-versions`), not string order. Livepatch can make a stale kernel effectively patched; the livepatch docs page was not retrievable (404), so Livepatch is out of scope for now.

## 4. unattended-upgrades state and logs (host)

All from [Automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/):

- `/etc/apt/apt.conf.d/20auto-upgrades`: `APT::Periodic::Update-Package-Lists "1"` and `APT::Periodic::Unattended-Upgrade "1"`; value is days, `"0"` disables. Collect both.
- `/etc/apt/apt.conf.d/50unattended-upgrades`: origins, reboot behaviour, blocklist. Reading effective values with `apt-config dump` rather than parsing files is a suggestion (**UNVERIFIED**; `apt-config` was not fetched).
- Logs in `/var/log/unattended-upgrades/`, with dpkg detail in `unattended-upgrades-dpkg.log`. Push the newest log mtime and the last run's outcome line(s), not the full logs. The exact main log filename and line formats were not stated by the page (**UNVERIFIED**).
- Timers `apt-daily.timer` and `apt-daily-upgrade.timer` trigger the runs; `systemctl list-timers` shows last and next trigger. A disabled timer with `20auto-upgrades` still set means nothing runs.
- The default allows security only. Non-security pending updates are expected to accumulate unless `-updates` is uncommented; the split in section 1 matters for judging this.

## 5. Ubuntu release EOL (worker)

Host side: read `/etc/os-release` (`VERSION_ID`, `VERSION_CODENAME`) and push it. endoflife.date's own `versionCommand` for Ubuntu in the API response is `cat /etc/os-release`.

Worker side, endoflife.date API v1, verified live:

- `GET https://endoflife.date/api/v1/products/ubuntu/releases/24.04` returns `result` with `isEol`, `eolFrom`, `isEoas`, `eoasFrom`, `isEoes`, `eoesFrom`, `isMaintained`, `isLts`, `latest {name, date, link}`, plus `schema_version`, `generated_at`.
- Dates seen: 24.04 `eolFrom` 2029-05-31, `eoesFrom` 2034-04-25; 22.04 `eolFrom` 2027-06-01, `eoesFrom` 2032-04-21. Use `eolFrom` for standard support end and `eoesFrom` for the ESM horizon. A host on an LTS past `eolFrom` without Pro gets no security fixes.
- `GET /api/v1/products/ubuntu` returns the whole product with all releases in one call; one request per product per poll is enough.
- Cache headers observed: `cache-control: public,max-age=0,must-revalidate` with an `etag`, so conditional requests (`If-None-Match`) work. The API docs page is a Swagger UI that yielded no text, so no documented rate limit was found. **UNVERIFIED**: poll at most a few times a day, consistent with the existing worker poll floor (commit 59229a9).
- `releases/latest` returns the newest release (for example 26.10), not the newest LTS; do not use it to judge "latest LTS".

## 6. k3s latest patch in the node's minor (worker)

Host side: the node's k3s version string, for example `v1.33.9+k3s1` (**UNVERIFIED** primary doc for the exact command; `k3s --version` and the node `kubeletVersion` are the usual sources). Push the full string; the worker derives the minor.

Worker side, two candidate references:

1. **update.k3s.io channel server (preferred).** k3s docs define channels `stable`, `latest`, and one `vX.Y` channel per Kubernetes minor, "including end-of-life versions"; a minor channel selects "the latest release available for that minor version, not necessarily a stable release". Source: [k3s Manual Upgrades](https://docs.k3s.io/upgrades/manual). Channel list: `https://update.k3s.io/v1-release/channels`, with the project at [rancher/channelserver](https://github.com/rancher/channelserver).
   - Verified live: `GET https://update.k3s.io/v1-release/channels` returns JSON `{data: [{name, latest, latestRegexp, excludeRegexp, links}]}`. One call yields every minor's latest patch (for example `v1.33` -> `v1.33.13+k3s2`, `v1.34` -> `v1.34.12+k3s1`; `stable` -> `v1.36.5+k3s1`). Pre-release builds are excluded from `vX.Y` channels by `excludeRegexp ^[^+]+-`.
   - `GET /v1-release/channels/v1.33` answers with a redirect to the GitHub release tag (`.../releases/tag/v1.33.13+k3s2`); the worker could read the `Location` header, but the collection endpoint is simpler. HEAD returned 405, so use GET.
   - The collection JSON shape is observed, not documented on docs.k3s.io; validate with Zod and treat shape changes as a soft failure.
   - Compare using semver on the part before `+`, then the `+k3sN` suffix as a tiebreak (a `+k3s2` rebuild can follow `+k3s1` of the same patch).
2. **GitHub Releases API** (`api.github.com/repos/k3s-io/k3s/releases`): works, but the unauthenticated limit observed in `x-ratelimit-limit` is 60 requests per hour per IP and pre-releases need filtering. Fallback only.

"Latest" is minor-scoped. A node on an EOL minor is not "up to date" even at that minor's latest patch; report both signals.

## 7. k3s minor EOL (worker)

- **endoflife.date has no `k3s` product.** `/api/v1/products/k3s` returned 404; the product list has `kubernetes` and `rancher` but nothing for k3s.
- k3s tracks upstream Kubernetes minors (channel and release naming match, for example k3s v1.37.1 and Kubernetes v1.37.1), so the practical EOL reference is the upstream `kubernetes` product: `GET https://endoflife.date/api/v1/products/kubernetes/releases/1.33` returned `eolFrom` 2026-06-28, `isEol` true, `latest.name` 1.33.13.
- **This is an inference, not a k3s-published policy.** docs.k3s.io does not state a support or EOL policy in the pages checked (upgrades index, manual, automated). SUSE publishes per-minor k3s support matrices (for example `suse.com/suse-k3s/support-matrix/all-supported-versions/k3s-v1-34/`), the vendor source for supported versions; they were not fetched here. Open item: treat upstream EOL as k3s EOL, or maintain a table from the SUSE matrix.
- The channel list shows old minors (`v1.16`) whose `latest` has stopped moving. Not a reliable EOL signal.

## Suggested pushed payload (for the next ticket)

Host-read, per push: `os_release {version_id, codename}`; `apt {pending_security, pending_other, held_back, security_packages[], list_age}`; `pro {attached, esm_infra, esm_apps, security_status counts}`; `reboot {required, since, packages[]}`; `kernel {running, newest_installed}`; `unattended {update_lists_days, upgrade_days, timers_active, last_run_at, last_run_ok}`; `k3s {version}`.

Worker-derived, never pushed: Ubuntu `eolFrom` / `eoesFrom`, k3s minor latest patch, k3s minor EOL, and the derived "behind by N patches" and "days to EOL".

## Open items

- Verify the `apt-get -s` `Inst` origin format and the `uname -r` vs `linux-image` comparison on a real Ubuntu 22.04 and 24.04 droplet.
- Confirm exact unattended-upgrades log filenames and success markers.
- Pro client docs moved (`documentation.ubuntu.com/pro-client` redirects, some deep links 404); re-find primary pages for `pro status --format json` field names before parsing them.
- Decide the k3s EOL source (upstream via endoflife.date vs SUSE support matrix).
