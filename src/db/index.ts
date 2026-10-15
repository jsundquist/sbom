import { drizzle } from 'drizzle-orm/node-postgres';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import { Pool } from 'pg';
import { env } from '@/lib/env';
import * as schema from './schema';

/** Driver-agnostic database type (node-postgres in production, PGlite in tests). */
export type Db = PgDatabase<PgQueryResultHKT, typeof schema>;

const globalForDb = globalThis as unknown as { sbomDb?: Db; sbomPool?: Pool };

export function getDb(): Db {
  if (!globalForDb.sbomDb) {
    globalForDb.sbomPool = new Pool({ connectionString: env().DATABASE_URL, max: 10 });
    globalForDb.sbomDb = drizzle(globalForDb.sbomPool, { schema }) as unknown as Db;
  }
  return globalForDb.sbomDb;
}

/** Overrides the database used by route handlers (tests). */
export function setDb(db: Db) {
  globalForDb.sbomDb = db;
}

export async function closeDb() {
  await globalForDb.sbomPool?.end();
  globalForDb.sbomDb = undefined;
  globalForDb.sbomPool = undefined;
}

export { schema };
