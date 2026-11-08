import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { requireOwner } from '@/server/auth';
import { parseDays } from '@/server/api';
import { getSummaryTrend } from '@/server/trends';

/** Daily totals across all applications, oldest first (`?days=` window, default 90, max 365). */
export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  return NextResponse.json({ points: await getSummaryTrend(getDb(), parseDays(new URL(req.url).searchParams.get('days'))) });
}
