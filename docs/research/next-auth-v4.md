# W-003: is `next-auth@4.24.15` (v4, npm `latest`) a good fit for Next 16.4.1?

Researched 2026-10-30, follow-up to `docs/research/auth-fit.md` (branch `research/auth-fit`). Sources: npm registry, GitHub
security advisories via `gh api repos/nextauthjs/next-auth/security-advisories`, official docs (next-auth.js.org, nextjs.org,
docs.github.com), the published `next-auth@4.24.15` tarball source, and a throwaway smoke app (next 16.4.1 + next-auth 4.24.15,
`next build` + `next start`, driven with curl). Labels: **[docs]** official doc, **[source]** read in the 4.24.15 package,
**[tested]** observed in the smoke app, **[inference]** my reasoning only.

## Verdict

Yes, it fits technically, with two things to design around: (1) v4 has **no `trustHost` option and reads the public URL only
from `process.env`** (`NEXTAUTH_URL` / `AUTH_TRUST_HOST`), so "everything through `env()`" needs a small shim; (2) `jwt.maxAge`
must be set explicitly or tokens stay valid server-side for 30 days even if `session.maxAge` is 7 days. Everything else asked
(proxy gating, GitHub id allow-list, stateless JWT) worked in a real Next 16.4.1 build. v4 is the old line; v5 is still `beta`
(auth-fit.md), so v4 is the only stable release, but it is in maintenance mode and its docs predate Next 16 `proxy`.

## 1. Advisories vs 4.24.15

`gh api repos/nextauthjs/next-auth/security-advisories` (all `published`), versions as listed by the advisory:

| Advisory | Sev | v4 range | Fixed in v4 | 4.24.15 affected? |
|---|---|---|---|---|
| GHSA-xmf8-cvqr-rfgj / CVE-2026-73418 (`getToken()` throws on malformed Bearer) | high | >= 4.0.6, <= 4.24.14 | 4.24.15 | No |
| GHSA-x445-f3h2-j279 / CVE-2026-73419 (state/nonce/PKCE cookies not bound to provider) | medium | <= 4.24.14 | 4.24.15 | No |
| GHSA-7rqj-j65f-68wh / CVE-2026-73420 (email normalizer homoglyph `@`) | high | >= 4.10.3, < 4.24.15 | 4.24.15 | No (and email provider unused) |
| GHSA-8fpg-xm3f-6cx3 / CVE-2026-73421 (config error makes `auth` object truthy, existence checks fail open) | low | **v5 only** (`>= 5.0.0-beta.0, <= beta.31`) | n/a | **Not applicable to v4** |
| GHSA-5jpx-9hw9-2fx4 (email misdelivery) | medium | < 4.24.12 | 4.24.12 | No |
| CVE-2023-48309 (user mocking bypass in middleware) | medium | < 4.24.5 | 4.24.5 | No |
| Older (2021-2023): CVE-2023-27490 state/PKCE <4.20.1, CVE-2022-39263, -35924, -31186, -31127, -31093, -29214, -24858, 2021-21310 | various | all < 4.20.1 | earlier | No |

- The three 2026 advisories that hit v4 were all fixed together in **4.24.15 (published 2026-07-20)**, the current `latest`. [tested: advisory API]
- **Fail-open (73421) is v5-specific.** In v4 the equivalent path is [source]: `withAuth` returns a redirect to
  `/api/auth/error?error=Configuration` when no secret is available (`next/middleware.js`), and `AuthHandler` returns a 500 with
  "problem with the server configuration" on `MissingSecret` in production (`core/lib/assert.js`). A missing secret does not grant access.
  Caveat [inference]: this is only fail-closed if gating tests `token?.<owner-id> === OWNER` (never `!!token`), and the
  proxy matcher actually covers the route.
- Dependency audit [tested]: `npm audit --omit=dev` in the smoke app: 0 vulnerabilities. Resolved `jose@4.15.9` (jose's own
  advisories are for <= 4.15.4), `openid-client@5.7.1`, `cookie@0.7.2`, `uuid@11.1.1`. 85 packages in the tree incl. next/react.
- Peer deps [npm]: `next ^12.2.5 || ... || ^16`, `react ^17 || ^18 || ^19`; `@auth/core` and `nodemailer` peers are optional.
  No peer warnings with next 16.4.1 / react 19 [tested].

## 2. Route gating under Next 16 `proxy`

- Next 16: file is `proxy.ts`, must export a function as default or named `proxy`; runtime is Node.js and cannot be set. [docs]
  https://nextjs.org/docs/app/api-reference/file-conventions/proxy
- The v4 docs (https://next-auth.js.org/configuration/nextjs) say nothing about Next 16 or `proxy.ts`; they only show `middleware.ts`. [docs]
- **`withAuth` as the default export of the proxy file works** [tested]: `next build` lists `Proxy (Middleware)`; with
  `callbacks.authorized({ req, token })` anon page -> 307 to the configured sign-in page, anon `GET /api/v1/items` -> 307
  (a redirect, not a 401), owner cookie -> 200, other-user cookie -> 307, `POST /api/v1/upload` with no cookie -> 200 (allowed
  through by checking `req.method` and path in `authorized`).
- **Custom proxy with `getToken` also works** [tested]: `export async function proxy(req)`; same results but API paths return a
  JSON 401 instead of a redirect, which is better for `GET /api/v1/*` consumers. Garbage cookie -> 401, malformed
  `Authorization: Bearer %E0%A4%A` on a gated route -> 401 (no throw; 4.24.15 wraps `decodeURIComponent` in try/catch, [source] `jwt/index.js`).
- **Method gating is not a matcher feature.** The matcher takes paths plus `has`/`missing` on header/query/cookie, not HTTP
  method [docs, proxy page]. To gate `GET /api/v1/*` but not upload POSTs, match broadly and branch on `req.method` + pathname inside
  the proxy / `authorized` callback (done in the smoke app). Alternative: the upload path only pass-through, everything else gated.
- `withAuth` internals worth knowing [source `next/middleware.js`]: it skips anything starting with the auth base path, the
  configured `pages.signIn`/`pages.error`, `/_next` and `/favicon.ico` (so `/login` page must be set as `pages.signIn` or it
  redirects forever); it computes the auth base path from `process.env.NEXTAUTH_URL` (default `/api/auth`); it takes `secret`
  from `options.secret` first, else `NEXTAUTH_SECRET`/`AUTH_SECRET` (so pass it explicitly). Its `authorized` default is `!!token`; override it.
- Next's own caveats still apply [docs, proxy page + auth guide]: `_next/data` always runs proxy; Server Functions are POSTs to
  their route so an excluded path skips proxy; proxy should not be the only check. Keep a `requireOwner()` (e.g. `getServerSession(authOptions)`
  or `getToken`) in `src/server/inventory.ts` reads / route handlers. `getServerSession(authOptions)` in RSC/route handlers
  awaits `headers()`/`cookies()`, so it is compatible with Next 15+/16 async request APIs [source `next/index.js`].
- **Secure cookie name trap** [tested, source `jwt/index.js`]: `getToken`/`withAuth` pick the cookie name from
  `process.env.NEXTAUTH_URL?.startsWith("https://")`: `__Secure-next-auth.session-token` on https, `next-auth.session-token`
  otherwise. With `NEXTAUTH_URL=https://...` the plain-name cookie was rejected and the `__Secure-` one accepted. Setting
  `NEXTAUTH_URL` (or `useSecureCookies` in authOptions plus `secureCookie`/`cookieName` in `getToken`) consistently everywhere is required;
  `withAuth` has no `secureCookie` option, only `cookies.sessionToken.name`.

## 3. Public URL, host trust, explicit config

- **No `trustHost` option in v4.** Origin is computed per request in `utils/detect-origin.js` [source]:
  1. if `process.env.NEXTAUTH_URL` is set, use it (ignores `Host`/`X-Forwarded-*`);
  2. else if `process.env.VERCEL` or `process.env.AUTH_TRUST_HOST` is set, build `proto://x-forwarded-host ?? host`
     (proto from `x-forwarded-proto`, defaults https);
  3. else `undefined`, and `parseUrl` falls back to **`http://localhost:3000/api/auth`**.
- [tested] with neither set, a request with hostile `Host`/`X-Forwarded-Host: evil.example` produced
  `callbackUrl: http://localhost:3000/api/auth/callback/github` (wrong, but not attacker-controlled) and logged
  `[next-auth][warn][NEXTAUTH_URL]`. With `NEXTAUTH_URL=https://sbom.example.com` plus `AUTH_TRUST_HOST=1`, hostile
  `X-Forwarded-Host` was **ignored** (URL stayed `https://sbom.example.com/...`). With only `AUTH_TRUST_HOST=1`, the callback URL
  became `https://evil.example/api/auth/callback/github`, i.e. trusts the header. **Recommendation: set `NEXTAUTH_URL` and do not set
  `AUTH_TRUST_HOST`.**
- Docs: https://next-auth.js.org/configuration/options says to set `NEXTAUTH_URL` to the canonical URL in production; it does not
  mention reverse proxies, `X-Forwarded-Host`, `AUTH_TRUST_HOST` or `trustHost` (the `AUTH_TRUST_HOST` behaviour is only in source). [docs, source]
- **Explicit config in `authOptions`:** works for `secret`, `session.strategy/maxAge`, `jwt.maxAge`, `providers`
  (`GithubProvider({ clientId, clientSecret })` is the documented v4 shape; used in smoke app, `providers` listing showed `github`) [tested].
  Not available as options: the public URL. Workaround [tested]: assign `process.env.NEXTAUTH_URL = env().PUBLIC_URL` at the top of the module that
  builds `authOptions` (imported by both the `[...nextauth]` route and `proxy.ts`); `detectOrigin` reads it per request, and
  the callback URL and the `__Secure-` cookie decision both followed it. It is one deliberate `process.env` write, an exception to
  "read config via `env()`" worth an inline comment. Because the proxy and route bundles load separately, set it in the shared module (each imports it).
- The v4 route handler also falls back to `process.env.NEXTAUTH_SECRET || AUTH_SECRET` only when `options.secret` is unset [source], so an explicit secret avoids env reads.
- `session.maxAge` / `jwt.maxAge` trap [source `core/init.js`, `core/routes/callback.js`]: docs say `jwt.maxAge` "defaults to `session.maxAge`"
  [docs], but `init.js` hard-codes the jwt default at 30 days and sign-in calls `jwt.encode({...jwt, token})`, so the token's
  internal `exp` is 30 days while only the cookie expiry follows `session.maxAge` (7 days). A copied cookie would still decrypt
  for 30 days. **Set both `session.maxAge` and `jwt.maxAge` to 604800.** (`/api/auth/session` refresh re-encodes with `session.maxAge`.)
  I did not test the 30-day case end to end; this is from reading the source.
- Secret rotation: v4 `secret` is a single string and `jwt.decode` takes one secret [source]; no array form like v5. To rotate,
  supply custom `jwt.encode/decode` or accept that a rotation logs the owner out (fine for one owner).
- Outbound HTTP: sign-in calls GitHub (token exchange, `/user`, possibly `/user/emails`) from the web process via `openid-client`
  and `fetch` [source `providers/github.js`]. Same AGENTS.md "external HTTP only from `src/worker/`" exception issue as auth-fit.md.

## 4. Restricting to one numeric GitHub id

- GitHub `GET /user` returns `id` as `integer, int64` [docs: https://docs.github.com/en/rest/users/users#get-the-authenticated-user].
  v4's GitHub provider `profile()` maps `id: profile.id.toString()` [source `providers/github.js`], so `user.id` and `token.sub` are the id as a string.
  The raw GitHub body is passed as `profile` to the callbacks.
- `signIn({ account, profile })` returns false to deny [docs: https://next-auth.js.org/configuration/callbacks]. Pattern [tested for the jwt claim and cookie checks]:
  `return account?.provider === 'github' && String(profile?.id) === OWNER_ID`. Compare as strings (or `Number`) deliberately; never `login` or `email`.
  I did not run a live GitHub OAuth round trip (no registered OAuth app), so the `signIn` callback itself was only exercised by source reading and the provider listing.
- `jwt` callback receives `profile`/`account`/`user` only on the first call after sign-in; later calls only `token` [docs]. Copy the
  id into the token then (`token.ghid = String(profile.id)`); `token.sub` already equals the id string [source `callback.js`] so you may just use `sub`.
- **Re-check on every request:** compare the claim to the *current* configured owner id in `proxy.ts`/`authorized` and in the `requireOwner()` DAL
  helper (do not trust `token.ghid` existing). [tested]: owner-id cookie -> 200, other id -> 401/307, garbage cookie -> 401. This means
  changing `OWNER_ID` in config revokes all other tokens immediately. It does **not** re-ask GitHub; a stolen valid cookie for the owner
  stays valid until `exp` (7 days if `jwt.maxAge` set) or secret rotation; v4 JWT mode has no server-side revocation. [source/inference]
- Also set `session` callback to expose only what the UI needs; the default session returns only name/email/image [docs].

## 5. JWT mode on a read-only rootfs

- Default strategy is `jwt` when no adapter is configured (`strategy: authOptions.adapter ? "database" : "jwt"`) [source `core/init.js`];
  the docs page is internally inconsistent on this, so set `session: { strategy: 'jwt' }` explicitly.
- A grep of the whole 4.24.15 package for `fs`, `os`, `writeFile`, `tmpdir` found no filesystem use [source]. State lives in
  cookies (session JWE, CSRF token, callback-url, and for OAuth the state/PKCE cookies). So no writable path is needed by next-auth itself. [source, strong]
- Not tested under `read_only: true` Docker; the smoke app ran on a normal fs. Next's own `.next/cache` tmpfs need (auth-fit.md) is unaffected. [unverified in compose]

## Verified vs unverified

Verified (advisory API / source / smoke app on next 16.4.1): 4.24.15 is the fixed version for the three 2026 v4 advisories; 73421
is v5-only; `withAuth` default export and custom `getToken` proxy both work under Next 16 `proxy`; API vs page behaviours
and the method-based upload bypass; malformed Bearer does not throw; origin detection order and the hostile-header behaviour;
`process.env.NEXTAUTH_URL` assignment from a shared module works; `__Secure-` cookie name coupling; owner-id claim check; no `fs` use in the package.

Unverified: a live GitHub OAuth sign-in (signIn/jwt callbacks run with a real `profile`); the 30-day `jwt.maxAge` default observed
only in source; behaviour under compose `read_only: true`; whether other advisory databases (e.g. npm audit later) list more issues
than the repo's advisory feed; how long v4 gets security patches (no EOL statement found in primary sources checked).

## Fit against repo rules (summary)

| Rule | v4 |
|---|---|
| `env()` only | Everything explicit in `authOptions` except the public URL, which needs one `process.env.NEXTAUTH_URL = env().X` assignment |
| Fail-closed | Missing secret errors out; still test `token.sub === OWNER` and an "unconfigured app denies" e2e |
| Layering | `authOptions` in `src/server/` (imports `lib/`), `proxy.ts` at `src/`; `components/` must not import it |
| Bearer uploads | Pass through by `req.method === 'POST'` + upload path in the proxy; keep existing token auth in the route |
| External HTTP | Needs the ADR exception for GitHub OAuth (same as v5 and hand-rolled) |
| Dependencies | `next-auth` pulls `jose@4`, `openid-client@5`, `preact`, `oauth`, `cookie`, `uuid`; pin exact `4.24.15` and let Dependabot propose bumps |
