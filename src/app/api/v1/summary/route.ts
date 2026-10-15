import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { getOverview } from '@/server/inventory';

export async function GET() {
  return NextResponse.json(await getOverview(getDb()));
}
