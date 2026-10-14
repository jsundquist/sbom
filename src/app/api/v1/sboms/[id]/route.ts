import { getDb } from '@/db';
import { jsonError, parseId } from '@/server/api';
import { getSbomDocument } from '@/server/inventory';

/** Downloads the original SBOM document. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const id = parseId((await params).id);
  const row = id ? await getSbomDocument(getDb(), id) : null;
  if (!row) return jsonError(404, 'SBOM not found');
  const filename = `${row.projectName}-${row.version ?? id}.sbom.json`.replace(/[^\w.@-]+/g, '_');
  return new Response(JSON.stringify(row.document, null, 2), {
    headers: { 'content-type': 'application/json', 'content-disposition': `attachment; filename="${filename}"` },
  });
}
