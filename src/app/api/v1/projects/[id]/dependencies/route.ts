import { NextResponse } from 'next/server';
import { getDb } from '@/db';
import { jsonError, parseId } from '@/server/api';
import { getDependencyGraph } from '@/server/inventory';

type Ctx = { params: Promise<{ id: string }> };

/** Dependency edges of the project's latest SBOM (`?sbom=<id>` selects an older upload). */
export async function GET(req: Request, { params }: Ctx) {
  const id = parseId((await params).id);
  const sbomParam = new URL(req.url).searchParams.get('sbom');
  const sbomId = sbomParam ? parseId(sbomParam) : undefined;
  const graph = id && sbomId !== null ? await getDependencyGraph(getDb(), id, sbomId) : null;
  if (!graph) {
    return jsonError(404, 'Project not found');
  }
  return NextResponse.json(graph);
}
