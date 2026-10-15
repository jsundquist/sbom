import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/db';
import { env } from '@/lib/env';
import { SbomParseError } from '@/sbom/parse';
import { checkUploadToken, jsonError } from '@/server/api';
import { IngestError, ingestSbom } from '@/server/ingest';

const field = z
  .string()
  .trim()
  .max(500)
  .optional()
  .transform((v) => v || undefined);
const metaSchema = z.object({ project: field, version: field, ref: field, commit: field, repository: field });

/**
 * Upload an SBOM (CycloneDX or SPDX JSON) as the request body.
 * Metadata comes from query parameters or X-Sbom-* headers: project, version, ref, commit, repository.
 */
export async function POST(req: Request) {
  const denied = checkUploadToken(req);
  if (denied) {
    return denied;
  }

  const limit = env().MAX_UPLOAD_BYTES;
  if (Number(req.headers.get('content-length') ?? 0) > limit) {
    return jsonError(413, `SBOM exceeds ${limit} bytes`);
  }
  const text = await req.text();
  if (Buffer.byteLength(text) > limit) {
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
  const meta = metaSchema.safeParse(Object.fromEntries(['project', 'version', 'ref', 'commit', 'repository'].map((k) => [k, pick(k)])));
  if (!meta.success) {
    return jsonError(400, meta.error.issues[0].message);
  }

  try {
    const result = await ingestSbom(getDb(), document, meta.data, { historyLimit: env().SBOM_HISTORY_LIMIT });
    return NextResponse.json({ ...result, url: new URL(`/projects/${result.projectId}`, url.origin).toString() }, { status: 201 });
  } catch (err) {
    if (err instanceof SbomParseError || err instanceof IngestError) {
      return jsonError(400, err.message);
    }
    throw err;
  }
}
