import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { requireOwner } from '@/server/auth';
import { listPackages } from '@/server/inventory';

export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  return NextResponse.json(await listPackages(getDb()));
}
