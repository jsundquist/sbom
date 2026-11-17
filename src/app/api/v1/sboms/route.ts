import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/db';
import { env } from '@/lib/env';
import { PROJECT_KINDS } from '@/lib/kinds';
import { parseTags } from '@/lib/tags';
import { SbomParseError } from '@/sbom/parse';
import { checkUploadToken, jsonError, readBodyLimited, requestActor } from '@/server/api';
import { IngestError, ingestSbom } from '@/server/ingest';

const field = z
  .string()
  .trim()
  .max(500)
  .optional()
  .transform((v) => v || undefined);
const kind = z.enum(PROJECT_KINDS, { error: `kind must be one of: ${PROJECT_KINDS.join(', ')}` }).optional();
const metaSchema = z.object({ project: field, version: field, ref: field, commit: field, repository: field, kind });
const META_FIELDS = ['project', 'version', 'ref', 'commit', 'repository', 'kind'];

/**
 * Upload an SBOM (CycloneDX or SPDX JSON) as the request body.
 * Metadata comes from query parameters or X-Sbom-* headers: project, version, ref, commit, repository, kind, tags.
 */
export async function POST(req: Request) {
  const denied = checkUploadToken(req);
  if (denied) {
    return denied;
  }

  const limit = env().MAX_UPLOAD_BYTES;
  const text = await readBodyLimited(req, limit);
  if (text === null) {
    return jsonError(413, `SBOM exceeds ${limit} bytes`);
  }

  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return jsonError(400, 'Request body must be a JSON SBOM document');
  }

  const url = new URL(req.url);
  const pick = (name: string) => url.searchParams.get(name) ?? req.headers.get(`x-sbom-${name}`) ?? undefined;
  const meta = metaSchema.safeParse(Object.fromEntries(META_FIELDS.map((k) => [k, pick(k)])));
  if (!meta.success) {
    return jsonError(400, meta.error.issues[0].message);
  }

  const tags = parseTags(pick('tags'));
  if (!tags.ok) {
    return jsonError(400, tags.error);
  }

  try {
    const result = await ingestSbom(
      getDb(),
      document,
      { ...meta.data, tags: tags.tags },
      { historyLimit: env().SBOM_HISTORY_LIMIT, actor: requestActor(req) },
    );
    return NextResponse.json({ ...result, url: new URL(`/projects/${result.projectId}`, url.origin).toString() }, { status: 201 });
  } catch (err) {
    if (err instanceof SbomParseError || err instanceof IngestError) {
      return jsonError(400, err.message);
    }
    throw err;
  }
}
