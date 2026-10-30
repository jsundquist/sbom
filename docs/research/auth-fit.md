# W-002: Auth.js v5 fit, and the cost of a minimal signed-cookie gate

Researched 2026-10-30 for map W-001. Repo state: Next.js 16.4.1 (`package.json` `^16.4.1`, installed 16.4.1), React 19.3, Zod 4, Node 22.
Sources are primary only (official docs, GitHub security advisories via `gh api`, npm registry metadata). Items I could not
verify from a primary source are listed under "Unverified" at the end.

## Verdict

- Auth.js v5 **fits technically** on Next 16 (proxy supported, JWT sessions work with no adapter) and the current beta has no
  open advisories. Costs: it is still a `beta` tag (no GA v5 as of today), it had 4 advisories in the last year (3 in 2026-07), and it
  reads `AUTH_*` from the environment by convention, which collides with the repo's "config only through `env()`" rule.
- A hand-rolled gate with `jose` is small and is the pattern Next.js itself documents. For a single owner it is competitive on
  cost; the hard part (GitHub OAuth code flow) is the same code either way if GitHub OAuth is chosen.
- **Cross-cutting finding for W-003/W-004:** GitHub OAuth needs outbound HTTP (token exchange, `/user`) from the web app. AGENTS.md
  says "External HTTP only from `src/worker/`". That rule would need an explicit exception (or ADR) with either library. A
  password/TOTP/passkey gate has no outbound HTTP and avoids the conflict.

## 1. Next.js 16: middleware is now `proxy`

- `middleware` file convention is deprecated and renamed `proxy` in v16.0.0; proxy defaults to the Node.js runtime; the `runtime`
  option is not available in proxy files. Node runtime for middleware was stable from v15.5.0.
  Source: https://nextjs.org/docs/app/api-reference/file-conventions/proxy (Version history)
- Without a `matcher`, proxy runs on every request incl. `_next/static` and `public/`. Next's own examples exclude `api` in the
  matcher; **this repo must do the opposite** (include `/api/v1/*` GET, exclude upload POSTs or let them fall through to bearer
  auth). Same page, "Matcher" and "Negative matching".
- Execution order: `headers` from `next.config` run before proxy, so the repo's `securityHeaders()` still apply to redirects/401s. Same page, "Execution order".
- `_next/data` routes are always invoked through proxy even if excluded. Server Functions are POSTs to the route that uses them,
  so an excluded path skips them; "always verify authentication and authorization inside each Server Function rather than
  relying on Proxy alone". Same page.
- Next's auth guide: proxy is for optimistic cookie-only checks (no DB), "should not be your only line of defense"; do the real
  check close to data (a Data Access Layer). For Route Handlers: "Treat ... with the same security considerations as
  public-facing API endpoints". Source: https://nextjs.org/docs/app/guides/authentication
  Fit for this repo: reads already funnel through `src/server/inventory.ts`, so a `requireOwner()` call there (or in the thin route
  handlers) is a natural second layer behind the proxy.
- Proxy bypass has been a recurring CVE class; all fixed in 16.4.1:
  GHSA-492v-c6pp-mqqv / CVE-2026-44574 (dynamic route param injection), GHSA-267c-6grr-h53f / CVE-2026-44575 and
  GHSA-26hh-7cqf-hhc6 / CVE-2026-45109 (segment-prefetch routes), GHSA-6gpp-xcg3-4w24 / CVE-2026-64642 (Turbopack, single locale,
  fixed 16.2.11). 16.4.1 is also the fix for the 2026-10-14 criticals (GHSA-2464-fhr4-w9xw image optimizer RCE, GHSA-673q-mjm6-r5xr
  `use cache` RCE, GHSA-p3m5-59mp-jv5r Server Actions DoS). Source: `gh api repos/vercel/next.js/security-advisories`.
  Implication: do not rely on proxy alone; keep Next on latest patch (Dependabot already does).

## 2. Auth.js v5 (`next-auth`)

### Version and compatibility
- npm dist-tags: `latest` = 4.24.15, `beta` = 5.0.0-beta.32 (published 2026-07-20). v5 is installed with `next-auth@beta`.
  Source: npm registry (`npm view next-auth dist-tags`); install page https://authjs.dev/getting-started/installation
- 5.0.0-beta.32 peers: `next ^14 || ^15 || ^16`, `react ^18.2 || ^19`; depends on `@auth/core` 0.41.3 (exact). Fits Next 16.4.1 / React 19.
  Note the older `latest` v4 line pins peer `@auth/core 0.34.3` and lists Next up to 16 too, but v5 is the documented path for the App Router.
- Proxy: installation docs say on Next.js 16+ create `proxy.ts` with `export { auth as proxy } from "@/auth"`; proxy is optional
  and mainly keeps the session alive (expiry refresh). Authorization uses `callbacks.authorized`. Source: installation page;
  https://authjs.dev/reference/nextjs ("Middleware: optional, but recommended for keeping the session alive").

### JWT sessions, no adapter
- JWT is the default strategy unless an adapter is configured; with an adapter it defaults to `database` but can be forced to `jwt`.
  Token is an encrypted JWE in an HttpOnly cookie, encrypted with `AUTH_SECRET`. Default `session.maxAge` is 30 days.
  Source: https://authjs.dev/concepts/session-strategies, https://authjs.dev/reference/core
- Cannot revoke a JWT before expiry without a server-side blocklist; sign-out only deletes the cookie. For a single owner,
  mitigations: short `maxAge`, rotate `AUTH_SECRET` (the `secret` option accepts an array for rotation). Same sources.
- No DB tables needed, so no coupling to Drizzle/Postgres and no schema change.

### Public deploy behind a reverse proxy
- Auth.js trusts the incoming `Host` header, so `trustHost` must be true; the docs warn to ensure the platform sets `host` safely.
  Auto-set only on known platforms such as Vercel. `useSecureCookies` defaults true on https URLs. Source: https://authjs.dev/reference/core
- GitHub callback URL for Next is `https://<host>/api/auth/callback/github`; env vars `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET`.
  Source: https://authjs.dev/getting-started/providers/github
- Owner allow-list: the `signIn` callback returns false to deny (docs example filters on `profile?.email`). Source: reference/nextjs.
  For an allow-list you want the numeric GitHub account id, not login (logins can be renamed); GitHub's page says to revalidate
  identity each sign-in but does not name the stable field (see Unverified).

### Known advisories (GitHub Security Advisories for nextauthjs/next-auth)
| ID | Sev | Affects v5 | Fixed | Relevance here |
|---|---|---|---|---|
| GHSA-7rqj-j65f-68wh / CVE-2026-73420 | high | beta.1 - beta.31 | beta.32 | Email provider normalizer; not used with GitHub-only |
| GHSA-xmf8-cvqr-rfgj / CVE-2026-73418 | high | beta.0 - beta.31 | beta.32 | `getToken()` throws on malformed Bearer header; relevant if `getToken` is called on routes that also take upload bearer tokens |
| GHSA-x445-f3h2-j279 / CVE-2026-73419 | medium | beta.1 - beta.31 | beta.32 | OAuth state/nonce/PKCE cookies not bound to provider; relevant to OAuth |
| GHSA-8fpg-xm3f-6cx3 / CVE-2026-73421 | low | beta.0 - beta.31 | beta.32 | **Fail-open**: on a server config error (e.g. unset `AUTH_SECRET`) `auth` is a truthy error object, so `!!auth` passes everyone |
| GHSA-5jpx-9hw9-2fx4 | medium | < beta.30 | beta.30 | Email misdelivery |

- Net: pin `next-auth` to an exact `5.0.0-beta.32` or later (not `^`/`beta` tag drift; the repo's Dependabot would move it). Four of
  five advisories landed in Apr-Jul 2026 and were fixed in one release, which signals active maintenance and active churn.
- The fail-open advisory is directly on point for a gate: always test `auth?.user` (or the owner id), never `!!auth`, and add an
  e2e that an unconfigured app denies access. Fits the repo's fail-closed uploads precedent.
- Source: `gh api repos/nextauthjs/next-auth/security-advisories` (full list also has v4-era issues 2021-2025 for the open-redirect/state/PKCE class).

### Docker / read-only rootfs
- The repo does not use `output: 'standalone'`: the image copies `.next`, `src`, `node_modules` and runs `npm start`; compose runs
  `read_only: true` with tmpfs on `/tmp` and `/app/.next/cache` (`Dockerfile`, `docker-compose.yml`).
- Standalone, if adopted later, traces `node_modules` with `@vercel/nft` and emits `server.js`; `public` and `.next/static` must be
  copied by hand. Source: https://nextjs.org/docs/app/api-reference/config/next-config-js/output. Auth.js is plain
  `node_modules` JS and is traced like any dependency; proxy supports Docker and Node server deployments (proxy page, "Platform support").
- JWT mode keeps all state in the cookie, so no extra writable path should be needed; this is my inference from the strategy
  docs, not a stated guarantee. Verify by running the compose stack with the gate on (cheap, do in the build ticket).

### Fit against repo rules
- **`env()` rule:** Auth.js is designed around `AUTH_SECRET`, `AUTH_URL`, `AUTH_GITHUB_*` read from `process.env` (documented for
  `AUTH_SECRET` and the GitHub vars). To honour AGENTS.md, add them to the Zod schema in `src/lib/env.ts` and pass `secret`,
  `trustHost` and provider credentials explicitly from `env()`. `secret` and `trustHost` are documented config options; explicit
  provider `clientId/clientSecret` is not shown on the GitHub provider page (Unverified). Fall back is to set `process.env.AUTH_*`
  from `env()` at init, which is ugly.
- **Layering:** `src/auth.ts` would sit at repo root or `src/server/`; `components/` must not import it (only types).
- **Outbound HTTP:** see Verdict; Auth.js calls GitHub from the web process.
- **Bearer uploads:** unaffected if the matcher/`authorized` callback passes `POST /api/v1/.../upload` through to existing token auth. Keep
  `getToken()` off those paths (CVE-2026-73418).
- **MUI/CSP:** Auth.js ships a default sign-in page; a custom `pages.signIn` in MUI is probably wanted. CSP in `security-headers.ts` is
  unaffected for redirect-based OAuth.

## 3. Minimal alternative: signed cookie with `jose` (or nothing)

- Next.js documents exactly this pattern: `SignJWT` HS256 + `jwtVerify` with `algorithms: ['HS256']`, cookie via `cookies()` with
  `httpOnly`, `secure`, `sameSite: 'lax'`, `path: '/'`, expiry; proxy does the cookie-only optimistic check; a `verifySession()` DAL
  check goes close to data. Next recommends a library for "increased security and simplicity" but lists Jose and iron-session as session
  helpers. Source: https://nextjs.org/docs/app/guides/authentication
- `jose` 6.2.14 (2026-10-29). Its published advisories are all for old majors (JWE resource exhaustion <= 4.15.4, padding-oracle <3.11.4).
  Source: `gh api repos/panva/jose/security-advisories`; npm. `jose` works in the Node proxy runtime. Zero-dependency alternative is
  Node `crypto.createHmac` + `timingSafeEqual` on `payload.expiry.sig`, which removes the dependency but is more bespoke.
- **What you write** (my estimate, ~150-300 LOC plus tests):
  1. `env()` additions: `SESSION_SECRET` (min 32 chars), owner identity (e.g. GitHub numeric id, or password hash), `SESSION_MAX_AGE`.
  2. `src/lib/session.ts` sign/verify (pure, unit-testable under the existing PGlite-free vitest setup).
  3. `proxy.ts` with matcher covering pages and `GET /api/v1/*`, letting upload POSTs and `/login`, `/api/healthz` through.
  4. `requireOwner()` called in `src/server/inventory.ts` read paths or route handlers (defense in depth, per Next docs).
  5. Login/logout routes; if GitHub OAuth: authorize redirect, `state` + PKCE S256 cookie, token exchange, `/user` fetch, owner-id compare.
     GitHub supports `state` and PKCE `S256` (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps);
     the redirect URI must match the configured callback. Auth.js's CVE-2026-73419 (state cookie not bound to provider) shows this
     step is where hand-rolled code goes wrong, though with one fixed provider the binding bug does not apply.
  6. CSRF: `SameSite=Lax` plus POST-only logout plus an `Origin` check on state-changing routes (the repo has `src/server/origin.ts`, worth reading in W-004).
- **What you do not get for free:** session refresh, sign-in UI, secret rotation (can emulate with a key list), provider quirks, a
  maintained security patch stream. For one fixed provider and one owner these are small.
- **Password variant:** no outbound HTTP, no third-party; needs scrypt/argon2 (Node `crypto.scrypt` is built in) and login rate limiting
  (map W-001 already lists brute-force limiting as unspecified; the existing in-memory write rate limit is per-process).

## 4. Comparison for this repo

| Concern | Auth.js v5 beta.32 | `jose` hand-rolled |
|---|---|---|
| Next 16 proxy | Documented (`export { auth as proxy }`) | Documented pattern, you write it |
| No DB / adapter | Default JWT | Native |
| Maturity | Beta tag; 4 advisories in 2026 | Your code; `jose` itself clean for current major |
| `env()` rule | Friction (convention is `process.env.AUTH_*`) | Natural |
| Outbound HTTP from app | Yes (GitHub) | Yes if GitHub, none if password |
| New deps | `next-auth` + `@auth/core` tree | `jose` (or none) |
| OAuth correctness risk | Library handles state/PKCE | You own it |
| Revocation | None before expiry (JWT) | Same unless you add a server nonce |
| Fail-open risk | Documented footgun (CVE-2026-73421) | Your tests decide |

## Open items to carry into W-003 / W-004
1. Decide whether the outbound-HTTP-from-app exception for GitHub OAuth is acceptable (ADR), or choose password/passkey.
2. If Auth.js: pin exactly, test explicit-config path (no `process.env.AUTH_*`), add fail-closed test.
3. In every option: proxy for coverage + `requireOwner()` in `src/server/` reads; matcher must include `/api/v1/*` GET and explicitly pass upload POSTs.
4. Run the compose stack (read-only rootfs) with the gate enabled before calling it done.

## Unverified
- Whether Auth.js's GitHub provider accepts explicit `clientId`/`clientSecret` and whether `AUTH_TRUST_HOST` is honoured (docs pages fetched do not state it; read `@auth/core` source).
- Which GitHub profile field the provider maps to `user.id` and whether the numeric account id is exposed in the `signIn` callback `profile` (read GitHub REST "Get the authenticated user": `id`).
- That JWT mode writes nothing to disk (inference).
- LOC estimates are mine, not measured.
