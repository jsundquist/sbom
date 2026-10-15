import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { listVulnerabilities } from '@/server/inventory';

export async function GET() {
  return NextResponse.json(await listVulnerabilities(getDb()));
}
