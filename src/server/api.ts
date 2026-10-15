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

export { parseIdOrNull as parseId } from '@/lib/params';
