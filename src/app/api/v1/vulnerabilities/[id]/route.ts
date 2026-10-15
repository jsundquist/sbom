import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { jsonError } from '@/server/api';
import { getVulnerability } from '@/server/inventory';

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const vuln = await getVulnerability(getDb(), decodeURIComponent((await params).id));
  if (!vuln) {return jsonError(404, 'Vulnerability not found');}
  return NextResponse.json(vuln);
}
