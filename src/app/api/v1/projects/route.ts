import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { listProjects } from '@/server/inventory';

export async function GET() {
  return NextResponse.json(await listProjects(getDb()));
}
