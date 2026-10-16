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
 * Returns an error response when UPLOAD_TOKENS is configured and the request lacks a valid token.
 * With no tokens configured, uploads are open outside production; in production they fail closed
 * unless ALLOW_OPEN_UPLOADS=true.
 */
export function checkUploadToken(req: Request): NextResponse | null {
  const limited = checkRateLimit(req);
  if (limited) {
    return limited;
  }
  const { UPLOAD_TOKENS: tokens, ALLOW_OPEN_UPLOADS, NODE_ENV } = env();
  if (!tokens.length) {
    if (NODE_ENV === 'production' && !ALLOW_OPEN_UPLOADS) {
      return jsonError(503, 'Uploads are disabled: set UPLOAD_TOKENS (or ALLOW_OPEN_UPLOADS=true for local use)');
    }
    return null;
  }
  const token = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (token && tokens.some((t) => safeEqual(t, token))) {
    return null;
  }
  return jsonError(401, 'Invalid or missing upload token');
}

const windows = new Map<string, { start: number; count: number }>();

/** Clears rate-limit state (tests). */
export function resetRateLimits() {
  windows.clear();
}

function clientKey(req: Request) {
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
export function checkRateLimit(req: Request, now = Date.now()): NextResponse | null {
  const { WRITE_RATE_LIMIT: max, WRITE_RATE_WINDOW_SECONDS: seconds } = env();
  if (!max) {
    return null;
  }
  const key = clientKey(req);
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

export { parseIdOrNull as parseId } from '@/lib/params';
