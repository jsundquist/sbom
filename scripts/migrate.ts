// Applies pending SQL migrations from ./drizzle.
import path from 'node:path';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';
import { env } from '@/lib/env';

const pool = new Pool({ connectionString: env().DATABASE_URL });
await migrate(drizzle(pool), { migrationsFolder: path.resolve(import.meta.dirname, '..', 'drizzle') });
await pool.end();
console.log('Migrations applied');
