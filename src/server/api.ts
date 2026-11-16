import crypto from 'node:crypto';
import { NextResponse } from 'next/server';
import { env } from '@/lib/env';

export const jsonError = (status: number, error: string) => NextResponse.json({ error }, { status });

function safeEqual(a: string, b: string) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/**
 * Shared by the token checks: rate limit first (so guessing is throttled), then the bearer token. With no tokens
 * configured the action is open outside production and fails closed in production unless ALLOW_OPEN_UPLOADS=true.
 */
function checkBearer(req: Request, tokens: string[], names: { env: string; what: string; token: string }): NextResponse | null {
  const limited = checkRateLimit(req);
  if (limited) {
    return limited;
  }
  const { ALLOW_OPEN_UPLOADS, NODE_ENV } = env();
  if (!tokens.length) {
    if (NODE_ENV === 'production' && !ALLOW_OPEN_UPLOADS) {
      return jsonError(503, `${names.what} are disabled: set ${names.env} (or ALLOW_OPEN_UPLOADS=true for local use)`);
    }
    return null;
  }
  const token = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (token && tokens.some((t) => safeEqual(t, token))) {
    return null;
  }
  return jsonError(401, `Invalid or missing ${names.token} token`);
}

/** Uploads: a token from UPLOAD_TOKENS. Fail-closed in production without any (see checkBearer). */
export const checkUploadToken = (req: Request) =>
  checkBearer(req, env().UPLOAD_TOKENS, { env: 'UPLOAD_TOKENS', what: 'Uploads', token: 'upload' });

/** Deletes: a token from ADMIN_TOKENS only; an upload token does not delete. Fail-closed in production without any. */
export const checkAdminToken = (req: Request) =>
  checkBearer(req, env().ADMIN_TOKENS, { env: 'ADMIN_TOKENS', what: 'Deletes', token: 'admin' });

const windows = new Map<string, { start: number; count: number }>();

/** Clears rate-limit state (tests). */
export function resetRateLimits() {
  windows.clear();
}

/** Which budget a request spends. Auth traffic has its own bucket so unauthenticated /api/auth/* calls cannot starve uploads. */
export type RateScope = 'write' | 'auth';

function clientKey(req: Request, scope: RateScope) {
  return `${scope}:${clientAddress(req)}`;
}

function clientAddress(req: Request) {
  if (env().TRUST_PROXY) {
    const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
    return forwarded || req.headers.get('x-real-ip') || 'unknown';
  }
  // Without a trusted proxy the socket address is not exposed to route handlers, so all clients share one bucket.
  return 'direct';
}

/**
 * Fixed-window, in-memory limit per client for write requests. Runs before the token check so
 * token guessing is throttled too. State is per process; run one web replica or limit at the proxy.
 */
export function checkRateLimit(req: Request, now = Date.now(), scope: RateScope = 'write'): NextResponse | null {
  const { WRITE_RATE_LIMIT, AUTH_RATE_LIMIT, WRITE_RATE_WINDOW_SECONDS: seconds } = env();
  const max = scope === 'auth' ? AUTH_RATE_LIMIT : WRITE_RATE_LIMIT;
  if (!max) {
    return null;
  }
  const key = clientKey(req, scope);
  const windowMs = seconds * 1000;
  let entry = windows.get(key);
  if (!entry || now - entry.start >= windowMs) {
    // Drop expired entries so the map cannot grow without bound.
    for (const [k, v] of windows) {
      if (now - v.start >= windowMs) {
        windows.delete(k);
      }
    }
    entry = { start: now, count: 0 };
    windows.set(key, entry);
  }
  entry.count += 1;
  if (entry.count > max) {
    const retryAfter = Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000));
    const res = jsonError(429, 'Too many requests');
    res.headers.set('Retry-After', String(retryAfter));
    return res;
  }
  return null;
}

/**
 * Reads the request body as text, aborting as soon as it exceeds `limit` bytes instead of buffering it all.
 * Returns null when the limit is exceeded.
 */
export async function readBodyLimited(req: Request, limit: number): Promise<string | null> {
  if (Number(req.headers.get('content-length') ?? 0) > limit) {
    return null;
  }
  if (!req.body) {
    return '';
  }
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export { parseDays, parseIdOrNull as parseId } from '@/lib/params';
