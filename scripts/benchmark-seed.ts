// Synthetic, deterministic data for the scale benchmark (F-004, ADR 0005): many Projects of about 2,000 components each, a
// retained SBOM history per Project, and the enrichment tables the read model joins. Nothing here touches the network.
import { eq } from 'drizzle-orm';
import { schema, type Db } from '@/db';

const { projects, sboms, components, componentEdges, packages, packageVersions, vulnerabilities, versionVulnerabilities } = schema;
const { kevEntries, epssScores, projectSnapshots } = schema;

export interface BenchmarkOptions {
  projects: number;
  /** Components per SBOM. */
  components: number;
  /** SBOMs retained per Project, the last being the latest. */
  history: number;
  /** Distinct packages shared by every Project. */
  packages: number;
  seed: number;
  /** Projects seeded at once. */
  concurrency?: number;
  log?: (line: string) => void;
}

export const DEFAULTS: BenchmarkOptions = { projects: 100, components: 2000, history: 20, packages: 6000, seed: 20261116, concurrency: 4 };

/** Small, fast, seedable PRNG (mulberry32). */
export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
type Rng = () => number;
const int = (rng: Rng, n: number) => Math.floor(rng() * n);
const pick = <T>(rng: Rng, xs: readonly T[]) => xs[int(rng, xs.length)];

export interface UniversePackage {
  key: string;
  ecosystem: 'npm' | 'pypi';
  name: string;
  /** Oldest first; the last one is the latest release. */
  versions: string[];
}

export function buildUniverse(rng: Rng, size: number): UniversePackage[] {
  return Array.from({ length: size }, (_, i) => {
    const ecosystem = rng() < 0.88 ? 'npm' : 'pypi';
    const name = `${ecosystem === 'npm' ? pick(rng, ['', '', '', '@acme/', '@types/']) : ''}${pick(rng, WORDS)}-${pick(rng, WORDS)}-${i}`;
    const major = 1 + int(rng, 6);
    const versions = Array.from({ length: 6 }, (_, v) => `${major + Math.floor(v / 3)}.${(v * 3) % 9}.${int(rng, 12)}`);
    return { key: `${ecosystem}:${name}`, ecosystem, name, versions };
  });
}

const WORDS = ['core', 'utils', 'http', 'parse', 'stream', 'crypto', 'cli', 'log', 'cache', 'queue', 'auth', 'sql', 'json', 'yaml', 'path'];
const LICENSES = ['MIT', 'MIT', 'MIT', 'Apache-2.0', 'ISC', 'BSD-3-Clause', 'GPL-3.0-only', 'MIT OR Apache-2.0'];
const CHECKS = [
  'Code-Review',
  'Maintained',
  'Pinned-Dependencies',
  'Security-Policy',
  'License',
  'Vulnerabilities',
  'Dangerous-Workflow',
  'Branch-Protection',
];

const purlOf = (p: UniversePackage, version: string) => `pkg:${p.ecosystem}/${p.name.replace('@', '%40')}@${version}`;

interface Ref {
  pkg: number;
  /** Index into the package's versions. */
  v: number;
  license: string;
}

/** One Project's first SBOM: the most popular packages every app uses, then a popularity-skewed draw from the rest. */
function firstSbom(rng: Rng, universe: UniversePackage[], count: number): Ref[] {
  const core = Math.min(Math.floor(count * 0.2), universe.length);
  const chosen = new Set<number>(Array.from({ length: core }, (_, i) => i));
  while (chosen.size < Math.min(count, universe.length)) {
    chosen.add(core + Math.floor(Math.pow(rng(), 1.7) * (universe.length - core)));
  }
  const lag = int(rng, 4);
  return [...chosen].map((pkg) => ({
    pkg,
    v: Math.max(0, universe[pkg].versions.length - 1 - lag - int(rng, 2)),
    license: pick(rng, LICENSES),
  }));
}

/** The next SBOM of the same Project: a few dependencies dropped, added or bumped. */
function nextSbom(rng: Rng, universe: UniversePackage[], prev: Ref[]): Ref[] {
  const next: Ref[] = [];
  const have = new Set<number>();
  for (const r of prev) {
    const roll = rng();
    if (roll < 0.01) {
      continue;
    }
    const v = roll < 0.04 ? Math.min(universe[r.pkg].versions.length - 1, r.v + 1) : r.v;
    next.push({ ...r, v });
    have.add(r.pkg);
  }
  while (next.length < prev.length) {
    const pkg = int(rng, universe.length);
    if (!have.has(pkg)) {
      have.add(pkg);
      next.push({ pkg, v: universe[pkg].versions.length - 1 - int(rng, 3), license: pick(rng, LICENSES) });
    }
  }
  return next;
}

/** A CycloneDX document of roughly the size a Syft scan produces, and the edges that go with it. */
function cycloneDx(universe: UniversePackage[], refs: Ref[], name: string) {
  const comps = refs.map((r) => {
    const p = universe[r.pkg];
    const version = p.versions[r.v];
    return {
      'bom-ref': `${p.key}@${version}`,
      type: 'library',
      name: p.name,
      version,
      purl: purlOf(p, version),
      licenses: [{ license: { id: r.license } }],
      cpe: `cpe:2.3:a:${p.name}:${p.name}:${version}:*:*:*:*:*:*:*`,
      properties: [
        { name: 'syft:package:foundBy', value: 'javascript-lock-cataloger' },
        { name: 'syft:package:language', value: p.ecosystem === 'npm' ? 'javascript' : 'python' },
        { name: 'syft:location:0:path', value: '/pnpm-lock.yaml' },
      ],
    };
  });
  return { bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { component: { type: 'application', name } }, components: comps };
}

const chunk = <T>(xs: T[], size: number): T[][] =>
  Array.from({ length: Math.ceil(xs.length / size) }, (_, i) => xs.slice(i * size, (i + 1) * size));

const SEVERITIES = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'LOW', 'LOW'] as const;
const SCORE = { CRITICAL: 9.4, HIGH: 7.8, MEDIUM: 5.3, LOW: 3.1 } as const;

/** Packages, versions, vulnerabilities and exploit signals, as the worker would have left them. */
async function seedEnrichment(db: Db, rng: Rng, universe: UniversePackage[]) {
  const now = new Date();
  for (const rows of chunk(universe, 1000)) {
    await db.insert(packages).values(
      rows.map((p) => ({
        key: p.key,
        ecosystem: p.ecosystem,
        namespace: null,
        name: p.name,
        latestVersion: p.versions.at(-1)!,
        latestCheckedAt: now,
        latestReleasedAt: new Date(now.getTime() - int(rng, 900) * 86_400_000),
        sourceRepo: rng() < 0.7 ? `github.com/acme/${p.name.replace(/[@/]/g, '')}` : null,
        scorecardScore: rng() < 0.6 ? Math.round(rng() * 90) / 10 : null,
        scorecardChecks: rng() < 0.6 ? CHECKS.map((name) => ({ name, score: int(rng, 11), reason: 'benchmark' })) : null,
        deprecated: rng() < 0.01,
      })),
    );
    await db
      .insert(packageVersions)
      .values(rows.flatMap((p) => p.versions.map((version) => ({ packageKey: p.key, version, vulnsCheckedAt: now }))));
  }

  // Roughly one version in twenty is affected by something.
  const vulnCount = Math.max(5, Math.floor(universe.length * 0.12));
  const vulns = Array.from({ length: vulnCount }, (_, i) => {
    const severity = pick(rng, SEVERITIES);
    // The affected window sits in the versions projects actually run (indices 1-4 of 6), not the oldest ones.
    return {
      id: `GHSA-bench-${String(i).padStart(5, '0')}`,
      cve: `CVE-2026-${10000 + i}`,
      severity,
      pkg: int(rng, universe.length),
      start: 1 + int(rng, 3),
      width: 1 + int(rng, 2),
    };
  });
  await db.insert(vulnerabilities).values(
    vulns.map((v) => ({
      id: v.id,
      aliases: [v.cve],
      summary: `Benchmark vulnerability ${v.id} in ${universe[v.pkg].name}`,
      details: 'x'.repeat(600),
      severity: v.severity,
      score: SCORE[v.severity],
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      published: now,
      modified: now,
      references: [{ type: 'ADVISORY', url: `https://example.test/${v.id}` }],
    })),
  );
  await db.insert(versionVulnerabilities).values(
    vulns.flatMap((v) => {
      const p = universe[v.pkg];
      const fixed = p.versions[v.start + v.width];
      return p.versions
        .slice(v.start, v.start + v.width)
        .map((version) => ({ packageKey: p.key, version, vulnerabilityId: v.id, fixedVersions: fixed ? [fixed] : [] }));
    }),
  );
  await db
    .insert(epssScores)
    .values(vulns.map((v) => ({ cveId: v.cve, score: Math.round(rng() * 1000) / 1000, percentile: rng(), fetchedAt: now })));
  await db.insert(kevEntries).values(
    vulns
      .filter((_, i) => i % 40 === 0)
      .map((v) => ({
        cveId: v.cve,
        vendor: 'Benchmark',
        product: 'Benchmark',
        name: v.id,
        dateAdded: '2026-01-01',
        knownRansomwareUse: false,
      })),
  );
}

async function seedProject(db: Db, rng: Rng, universe: UniversePackage[], opts: BenchmarkOptions, index: number) {
  const name = `bench-app-${String(index + 1).padStart(3, '0')}`;
  const [project] = await db
    .insert(projects)
    .values({ name, repository: `github.com/acme/${name}` })
    .returning({ id: projects.id });
  const day = 86_400_000;
  let refs = firstSbom(rng, universe, opts.components);
  let latestSbomId = 0;
  let latestRefs = refs;
  for (let h = 0; h < opts.history; h++) {
    if (h > 0) {
      refs = nextSbom(rng, universe, refs);
    }
    const uploadedAt = new Date(Date.now() - (opts.history - 1 - h) * day);
    const [sbom] = await db
      .insert(sboms)
      .values({
        projectId: project.id,
        version: `1.${h}.0`,
        ref: 'refs/heads/main',
        commitSha: (index * 1000 + h).toString(16).padStart(40, '0'),
        format: 'CycloneDX',
        specVersion: '1.5',
        componentCount: refs.length,
        document: cycloneDx(universe, refs, name),
        uploadedAt,
      })
      .returning({ id: sboms.id });
    const ids: number[] = [];
    for (const part of chunk(refs, 4000)) {
      const inserted = await db
        .insert(components)
        .values(
          part.map((r) => {
            const p = universe[r.pkg];
            return {
              sbomId: sbom.id,
              name: p.name,
              version: p.versions[r.v],
              purl: purlOf(p, p.versions[r.v]),
              ecosystem: p.ecosystem,
              packageKey: p.key,
              type: 'library',
              licenses: r.license,
              supplier: null,
            };
          }),
        )
        .returning({ id: components.id });
      ids.push(...inserted.map((c) => c.id));
    }
    // About a tenth of the components are direct; the rest hang off an earlier one, a few off two.
    const direct = Math.max(1, Math.floor(ids.length / 10));
    const edges = ids.flatMap((childId, i): (typeof componentEdges.$inferInsert)[] => {
      if (i < direct) {
        return [{ sbomId: sbom.id, parentId: null, childId }];
      }
      const parents = [ids[int(rng, i)]];
      if (rng() < 0.08) {
        parents.push(ids[int(rng, i)]);
      }
      return parents.map((parentId) => ({ sbomId: sbom.id, parentId, childId }));
    });
    for (const part of chunk(edges, 10_000)) {
      await db.insert(componentEdges).values(part);
    }
    latestSbomId = sbom.id;
    latestRefs = refs;
  }
  await db.update(projects).set({ latestSbomId }).where(eq(projects.id, project.id));

  // A snapshot a day for the last 90 days, enough for the trend charts to have something to read.
  const base = latestRefs.length;
  await db.insert(projectSnapshots).values(
    Array.from({ length: 90 }, (_, d) => ({
      projectId: project.id,
      day: new Date(Date.now() - d * day).toISOString().slice(0, 10),
      components: base,
      vulnerableComponents: Math.floor(base * 0.06),
      vulnerabilities: Math.floor(base * 0.04),
      critical: 1,
      high: 4,
      medium: 9,
      low: 6,
      unknown: 0,
      outdatedComponents: Math.floor(base * 0.3),
      outdatedMajor: Math.floor(base * 0.05),
    })),
  );
}

/** Seeds an empty database. Returns the Project ids. */
export async function seedBenchmark(db: Db, partial: Partial<BenchmarkOptions> = {}) {
  const opts = { ...DEFAULTS, ...partial };
  const log = opts.log ?? (() => {});
  const universe = buildUniverse(mulberry32(opts.seed), opts.packages);
  await seedEnrichment(db, mulberry32(opts.seed + 1), universe);
  log(`enrichment: ${universe.length} packages`);
  let next = 0;
  let done = 0;
  const worker = async () => {
    for (let i = next++; i < opts.projects; i = next++) {
      await seedProject(db, mulberry32(opts.seed + 100 + i), universe, opts, i);
      log(`project ${++done}/${opts.projects}`);
    }
  };
  await Promise.all(Array.from({ length: opts.concurrency ?? 1 }, worker));
}
