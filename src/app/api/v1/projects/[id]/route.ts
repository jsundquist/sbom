import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { checkUploadToken, jsonError, parseId } from '@/server/api';
import { deleteProject } from '@/server/ingest';
import { getProject } from '@/server/inventory';

type Ctx = { params: Promise<{ id: string }> };

/** Project details with its latest SBOM's components (`?sbom=<id>` selects an older upload). */
export async function GET(req: Request, { params }: Ctx) {
  const id = parseId((await params).id);
  const sbomParam = new URL(req.url).searchParams.get('sbom');
  const sbomId = sbomParam ? parseId(sbomParam) : undefined;
  const project = id && sbomId !== null ? await getProject(getDb(), id, sbomId) : null;
  if (!project) return jsonError(404, 'Project not found');
  return NextResponse.json(project);
}

export async function DELETE(req: Request, { params }: Ctx) {
  const denied = checkUploadToken(req);
  if (denied) return denied;
  const id = parseId((await params).id);
  if (!id || !(await deleteProject(getDb(), id))) return jsonError(404, 'Project not found');
  return new Response(null, { status: 204 });
}
