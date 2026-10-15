// Seeds demo SBOMs. With --offline, also enriches them from canned data instead of OSV.dev / deps.dev.
//   npm run db:seed              # uploads demo SBOMs; the worker enriches them
//   npm run db:seed -- --offline # uploads and enriches without network access
import { closeDb, getDb } from '@/db';
import { ingestSbom } from '@/server/ingest';
import { enrich } from '@/worker/enrich';
import { DEMO_SBOMS, demoFetch } from './demo-data';

const db = getDb();
for (const { document, meta } of DEMO_SBOMS) {
  const r = await ingestSbom(db, document, meta);
  console.log(`Uploaded ${r.projectName} (${r.componentCount} packages)`);
}
if (process.argv.includes('--offline')) {
  const stats = await enrich(db, {
    fetchImpl: demoFetch,
    osvApiUrl: 'https://osv.demo',
    depsDevApiUrl: 'https://depsdev.demo',
    vulnTtlHours: 12,
    latestTtlHours: 24,
    force: true,
  });
  console.log('Enriched from demo data:', stats);
}
await closeDb();
