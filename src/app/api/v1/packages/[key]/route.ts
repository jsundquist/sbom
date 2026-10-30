import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { requireOwner } from '@/server/auth';
import { jsonError } from '@/server/api';
import { getPackage } from '@/server/inventory';

/** `key` is the URL-encoded package key, e.g. npm%3Alodash. */
export async function GET(req: Request, { params }: { params: Promise<{ key: string }> }) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const pkg = await getPackage(getDb(), decodeURIComponent((await params).key));
  if (!pkg) {
    return jsonError(404, 'Package not found');
  }
  return NextResponse.json(pkg);
}
