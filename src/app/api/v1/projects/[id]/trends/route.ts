import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { requireOwner } from '@/server/auth';
import { jsonError, parseDays, parseId } from '@/server/api';
import { getProjectTrend } from '@/server/trends';

/** Daily snapshots of one project, oldest first (`?days=` window, default 90, max 365). */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const id = parseId((await params).id);
  const points = id ? await getProjectTrend(getDb(), id, parseDays(new URL(req.url).searchParams.get('days'))) : null;
  if (!points) {
    return jsonError(404, 'Project not found');
  }
  return NextResponse.json({ points });
}
