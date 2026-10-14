import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { listPackages } from '@/server/inventory';

export async function GET() {
  return NextResponse.json(await listPackages(getDb()));
}
