import crypto from 'node:crypto';

/** A short, stable hash that identifies which token acted without revealing it. Null when there is no token. */
export function tokenFingerprint(token: string | null | undefined): string | null {
  if (!token) {
    return null;
  }
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 12);
}
