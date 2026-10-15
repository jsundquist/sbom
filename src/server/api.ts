import crypto from 'node:crypto';
import { NextResponse } from 'next/server';
import { env } from '@/lib/env';

export const jsonError = (status: number, error: string) => NextResponse.json({ error }, { status });

function safeEqual(a: string, b: string) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Returns an error response when UPLOAD_TOKENS is configured and the request lacks a valid token. */
export function checkUploadToken(req: Request): NextResponse | null {
  const tokens = env().UPLOAD_TOKENS;
  if (!tokens.length) return null;
  const token = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (token && tokens.some((t) => safeEqual(t, token))) return null;
  return jsonError(401, 'Invalid or missing upload token');
}

export { parseIdOrNull as parseId } from '@/lib/params';
