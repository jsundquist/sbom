import { execFileSync } from 'node:child_process';
import { Client } from 'pg';
import { E2E_DATABASE_URL } from '../../playwright.config';

export default async function globalSetup() {
  const client = new Client({ connectionString: E2E_DATABASE_URL });
  await client.connect();
  await client.query('DROP SCHEMA IF EXISTS public CASCADE; DROP SCHEMA IF EXISTS drizzle CASCADE; CREATE SCHEMA public;');
  await client.end();
  const env = { ...process.env, DATABASE_URL: E2E_DATABASE_URL };
  execFileSync('npx', ['tsx', 'scripts/migrate.ts'], { env, stdio: 'inherit' });
  execFileSync('npx', ['tsx', 'scripts/seed-demo.ts', '--offline'], { env, stdio: 'inherit' });
}
