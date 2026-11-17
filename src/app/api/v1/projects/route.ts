import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { normalizeRepository } from '@/lib/repository';
import { jsonError } from '@/server/api';
import { requireOwner } from '@/server/auth';
import { listProjects } from '@/server/inventory';

export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const raw = new URL(req.url).searchParams.get('repository')?.trim();
  const repository = raw ? normalizeRepository(raw) : undefined;
  if (repository === null) {
    return jsonError(400, 'repository must be a git remote or owner/repo');
  }
  return NextResponse.json(await listProjects(getDb(), { repository }));
}
