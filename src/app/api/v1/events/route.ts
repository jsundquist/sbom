import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { jsonError } from '@/server/api';
import { requireOwner } from '@/server/auth';
import { listEvents } from '@/server/events';

const MAX_LIMIT = 1000;

function intParam(value: string | null, min: number): number | undefined | null {
  if (value === null || value === '') {
    return undefined;
  }
  const n = Number(value);
  return Number.isInteger(n) && n >= min ? n : null;
}

/** The audit trail of mutations, newest first. `?limit` (1-1000) and `?offset`; the total is in `X-Total-Count`. */
export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const params = new URL(req.url).searchParams;
  const limit = intParam(params.get('limit'), 1);
  const offset = intParam(params.get('offset'), 0);
  if (limit === null || (limit !== undefined && limit > MAX_LIMIT) || offset === null) {
    return jsonError(400, `limit must be 1-${MAX_LIMIT} and offset 0 or more`);
  }
  const { items, total } = await listEvents(getDb(), { limit, offset });
  return NextResponse.json(items, { headers: { 'X-Total-Count': String(total) } });
}
