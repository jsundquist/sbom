import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { sql } from 'drizzle-orm';
import type { Db } from '@/db';
import { createTestDb } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
});
afterEach(() => close());

/** Column lists of the indexes on a table, e.g. ["parent_id"] or ["sbom_id"]. */
async function indexedColumns(table: string): Promise<string[]> {
  const res = await db.execute<{ indexdef: string }>(sql`SELECT indexdef FROM pg_indexes WHERE tablename = ${table}`);
  const rows = (res as unknown as { rows: { indexdef: string }[] }).rows;
  return rows.map((r) => /\(([^)]*)\)/.exec(r.indexdef)![1]);
}

describe('foreign keys that cascade need an index on the referencing column', () => {
  // Deleting a component cascades to component_edges through these two columns. Without an index Postgres scans every edge for
  // each deleted component, so pruning one old SBOM at 4M edges ran for over 9 minutes (docs/benchmark.md, F-006).
  test.each(['parent_id', 'child_id'])('component_edges is indexed on %s', async (column) => {
    expect(await indexedColumns('component_edges')).toContain(column);
  });
});
