import { getDb } from '@/db';
import { jsonError } from '@/server/api';
import { requireOwner } from '@/server/auth';
import { getMetrics } from '@/server/metrics';

export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  try {
    return new Response(await getMetrics(getDb()), {
      headers: { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store' },
    });
  } catch (err) {
    console.error('metrics: failed', err);
    return jsonError(500, 'Could not read metrics');
  }
}
