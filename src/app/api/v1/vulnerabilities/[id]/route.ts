import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { requireOwner } from '@/server/auth';
import { jsonError } from '@/server/api';
import { getVulnerability } from '@/server/inventory';

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const vuln = await getVulnerability(getDb(), decodeURIComponent((await params).id));
  if (!vuln) {
    return jsonError(404, 'Vulnerability not found');
  }
  return NextResponse.json(vuln);
}
