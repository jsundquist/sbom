import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { sql } from 'drizzle-orm';
import { schema, type Db } from '@/db';
import { loadComponents, type ComponentScope } from '@/server/inventory';
import { seedBenchmark } from '../../scripts/benchmark-seed';
import { createTestDb } from './helpers';

// Characterization test for loadComponents: the read model behind the overview, projects, packages and vulnerabilities pages.
// It pins the exact output on a seeded dataset so the load can be made cheaper (K-001) without changing what it returns.
// Regenerate the golden file on purpose with UPDATE_GOLDEN=1 and review the diff.
const GOLDEN = path.join(import.meta.dirname, '..', 'fixtures', 'load-components.golden.json');

let db: Db;
let close: () => Promise<void>;

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  await seedBenchmark(db, { projects: 3, components: 30, history: 2, packages: 60, seed: 11 });
  // The seeder stamps "now" into some columns and leaves most components clean; pin and enrich the data so the output is
  // stable and covers what the golden file is meant to pin. Dates sit far from the "abandoned" boundary on purpose.
  await db.execute(
    sql`UPDATE packages SET latest_released_at = CASE WHEN length(key) % 2 = 0 THEN TIMESTAMPTZ '2016-01-01' ELSE TIMESTAMPTZ '2099-01-01' END`,
  );
  await db.execute(sql`UPDATE vulnerabilities SET published = TIMESTAMPTZ '2025-01-01', modified = TIMESTAMPTZ '2025-01-01'`);
  // A quarter of the package versions get a vulnerability, a few get a second one; every third vulnerability is in the KEV catalog.
  await db.execute(sql`
    INSERT INTO version_vulnerabilities (package_key, version, vulnerability_id, fixed_versions)
    SELECT pv.package_key, pv.version, v.id, jsonb_build_array(split_part(pv.version, '.', 1) || '.99.0')
    FROM package_versions pv
    CROSS JOIN (VALUES (0), (1)) AS s(shift)
    JOIN (SELECT id, row_number() OVER (ORDER BY id) - 1 AS n FROM vulnerabilities) v
      ON v.n = (abs(hashtext(pv.package_key || pv.version)) + s.shift) % (SELECT count(*) FROM vulnerabilities)
    WHERE abs(hashtext(pv.package_key)) % 4 = 0 AND (s.shift = 0 OR abs(hashtext(pv.version)) % 3 = 0)
    ON CONFLICT DO NOTHING`);
  await db.execute(sql`
    INSERT INTO kev_entries (cve_id, date_added, known_ransomware_use)
    SELECT aliases->>0, '2025-01-01', abs(hashtext(id)) % 2 = 0 FROM vulnerabilities WHERE abs(hashtext(id)) % 3 = 0
    ON CONFLICT DO NOTHING`);
  // Cover the statuses and update types the seeder does not produce.
  await db.execute(sql`UPDATE package_versions SET vulns_checked_at = NULL WHERE version LIKE '%.0'`);
  await db.execute(sql`UPDATE components SET purl = NULL, package_key = NULL, ecosystem = NULL WHERE id % 37 = 0`);
  await db.execute(sql`
    UPDATE packages p SET latest_version = (
      SELECT CASE length(p.key) % 3
        WHEN 0 THEN split_part(c.version, '.', 1) || '.' || split_part(c.version, '.', 2) || '.' || (split_part(c.version, '.', 3)::int + 1)
        WHEN 1 THEN split_part(c.version, '.', 1) || '.' || (split_part(c.version, '.', 2)::int + 1) || '.0'
        ELSE (split_part(c.version, '.', 1)::int + 1) || '.0.0' END
      FROM components c WHERE c.package_key = p.key LIMIT 1)
    WHERE length(key) % 5 <> 0`);
  await db.execute(sql`UPDATE packages SET latest_checked_at = NULL, latest_version = NULL WHERE length(key) % 5 = 0`);
});
afterEach(() => close());

/** One component per line, so a changed component is one changed line in review. */
const formatGolden = (g: { everything: unknown[]; scoped: Record<string, unknown[]> }) => {
  const list = (xs: unknown[]) => `[\n${xs.map((x) => `    ${JSON.stringify(x)}`).join(',\n')}\n  ]`;
  const scoped = Object.entries(g.scoped).map(([name, xs]) => `    ${JSON.stringify(name)}: ${list(xs)}`);
  return `{\n  "everything": ${list(g.everything)},\n  "scoped": {\n${scoped.join(',\n')}\n  }\n}\n`;
};

const byId = <T extends { id: number }>(list: T[]) => [...list].sort((a, b) => a.id - b.id);

async function snapshot() {
  const everything = await loadComponents(db);
  const vulnerable = everything.find((c) => c.vulns.length && c.packageKey);
  const olderSbom = (await db.select({ id: schema.sboms.id }).from(schema.sboms).orderBy(schema.sboms.id).limit(1))[0].id;
  const scopes: Record<string, ComponentScope> = {
    'package of a vulnerable component': { packageKey: vulnerable!.packageKey! },
    'components without a purl': { packageKey: `name:${everything.find((c) => !c.packageKey)!.name}` },
    'one vulnerability': { vulnerabilityId: vulnerable!.vulns[0].id },
    'an older SBOM': { sbomIds: [olderSbom] },
  };
  const scoped = Object.fromEntries(
    await Promise.all(Object.entries(scopes).map(async ([name, scope]) => [name, byId(await loadComponents(db, scope))])),
  );
  return JSON.parse(JSON.stringify({ everything: byId(everything), scoped }));
}

describe('loadComponents output', () => {
  test('the dataset exercises what the golden file is meant to pin', async () => {
    const list = await loadComponents(db);
    expect(list.some((c) => c.vulns.length > 0)).toBe(true);
    expect(list.some((c) => c.vulns.some((v) => v.kev))).toBe(true);
    expect(list.some((c) => c.vulns.some((v) => v.epss))).toBe(true);
    expect(new Set(list.map((c) => c.vulnStatus))).toEqual(new Set(['scanned', 'pending', 'unsupported']));
    expect(new Set(list.map((c) => c.versionStatus))).toEqual(new Set(['checked', 'pending', 'unsupported']));
    expect(list.some((c) => c.outdated)).toBe(true);
    expect(list.some((c) => c.maintenance.abandoned)).toBe(true);
  });

  test('matches the golden file', async () => {
    const actual = await snapshot();
    if (process.env.UPDATE_GOLDEN === '1') {
      fs.writeFileSync(GOLDEN, formatGolden(actual));
    }
    expect(actual).toEqual(JSON.parse(fs.readFileSync(GOLDEN, 'utf8')));
  });
});
