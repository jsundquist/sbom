import { headers } from 'next/headers';

/** Public origin of the dashboard, from the incoming request (honours reverse-proxy headers). */
export async function requestOrigin() {
  const h = await headers();
  const host = h.get('x-forwarded-host') ?? h.get('host') ?? 'localhost:3000';
  const proto = h.get('x-forwarded-proto') ?? (host.startsWith('localhost') ? 'http' : 'https');
  return `${proto}://${host}`;
}
