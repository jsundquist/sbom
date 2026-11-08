import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, setDb, type Db } from '@/db';
import { scorecardStatus, weakestChecks } from '@/lib/scorecard';
import { getPackage } from '@/server/inventory';
import { ingestSbom } from '@/server/ingest';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions, fakeFetch, type FakeApis } from './helpers';

describe('weakestChecks', () => {
  const checks = [
    { name: 'Maintained', score: 10 },
    { name: 'Fuzzing', score: 0 },
    { name: 'Pinned-Dependencies', score: 3 },
    { name: 'Signed-Releases', score: -1 },
    { name: 'License', score: 9 },
  ];
  test('returns the lowest scored checks and skips inconclusive ones (-1)', () => {
    expect(weakestChecks(checks, 2).map((c) => c.name)).toEqual(['Fuzzing', 'Pinned-Dependencies']);
  });
});

describe('scorecardStatus', () => {
  test.each([
    ['npm', null, 'pending'],
    ['npm', new Date(), 'checked'],
    ['apk', null, 'unsupported'],
  ] as const)('%s checked at %s is %s', (ecosystem, checkedAt, expected) => {
    expect(scorecardStatus(ecosystem, checkedAt, 7.5)).toBe(expected);
  });
  test('a checked package without a score is unsupported (no repo or no scorecard)', () => {
    expect(scorecardStatus('npm', new Date(), null)).toBe('unsupported');
  });
});

describe('Scorecard enrichment', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
    await ingestSbom(
      db,
      {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [
          { type: 'library', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15' },
          { type: 'library', name: 'norepo', version: '1.0.0', purl: 'pkg:npm/norepo@1.0.0' },
        ],
      },
      { project: 'app', version: '1' },
    );
  });
  afterEach(() => close());

  const APIS: FakeApis = {
    latest: { 'npm:lodash': '4.17.21', 'npm:norepo': '1.0.0' },
    sourceRepos: { 'npm:lodash@4.17.21': 'github.com/lodash/lodash' },
    scorecards: {
      'github.com/lodash/lodash': {
        overallScore: 7.5,
        checks: [
          { name: 'Maintained', score: 10 },
          { name: 'Fuzzing', score: 0, reason: 'project is not fuzzed' },
        ],
      },
    },
  };

  test('stores the score and weakest checks from the latest version’s source repo', async () => {
    await enrich(db, enrichOptions(APIS));
    const pkg = await getPackage(db, 'npm:lodash');
    expect(pkg?.scorecard).toMatchObject({
      status: 'checked',
      score: 7.5,
      sourceRepo: 'github.com/lodash/lodash',
      weakest: [{ name: 'Fuzzing', score: 0, reason: 'project is not fuzzed' }, { name: 'Maintained' }],
    });
  });

  test('a package with no source repo is unsupported, not an error', async () => {
    const stats = await enrich(db, enrichOptions(APIS));
    expect((await getPackage(db, 'npm:norepo'))?.scorecard).toMatchObject({ status: 'unsupported', score: null });
    expect(stats.errors).toBe(0);
  });

  test('a failed lookup is retried on the next run rather than reported as unsupported', async () => {
    const healthy = fakeFetch(APIS);
    const down: typeof fetch = async (input, init) =>
      new URL(input.toString()).pathname.startsWith('/v3/projects/') ? new Response('unavailable', { status: 503 }) : healthy(input, init);
    const quiet = { info() {}, warn() {}, error() {} };
    await enrich(db, { ...enrichOptions(APIS), fetchImpl: down, logger: quiet });
    expect((await getPackage(db, 'npm:lodash'))?.scorecard.status).toBe('pending');
    await enrich(db, enrichOptions(APIS));
    expect((await getPackage(db, 'npm:lodash'))?.scorecard).toMatchObject({ status: 'checked', score: 7.5 });
  });

  test('a package whose latest version is unknown settles as unsupported', async () => {
    await enrich(db, enrichOptions({ ...APIS, latest: { 'npm:lodash': '4.17.21' } }));
    expect((await getPackage(db, 'npm:norepo'))?.scorecard.status).toBe('unsupported');
  });

  test('is not re-fetched inside the TTL', async () => {
    await enrich(db, enrichOptions(APIS));
    const calls: string[] = [];
    await enrich(db, enrichOptions({ ...APIS, calls }));
    expect(calls.filter((c) => c.includes('/v3/projects/'))).toEqual([]);
    await db
      .update(schema.packages)
      .set({ scorecardCheckedAt: new Date(0) })
      .where(eq(schema.packages.key, 'npm:lodash'));
    await enrich(db, enrichOptions({ ...APIS, calls }));
    expect(calls.filter((c) => c.includes('/v3/projects/'))).toHaveLength(1);
  });
});
