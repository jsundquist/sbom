import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import type { Db } from '@/db';
import { ingestSbom } from '@/server/ingest';
import { aggregateUpgrades, getDependencyGraph, loadComponents, type ComponentVuln, type InventoryComponent } from '@/server/inventory';
import { enrich } from '@/worker/enrich';
import type { OsvVuln } from '@/worker/osv';
import { createTestDb, enrichOptions, fixture } from './helpers';

const vuln = (id: string, fixedVersions: string[], over: Partial<ComponentVuln> = {}): ComponentVuln => ({
  id,
  cve: id,
  aliases: [],
  summary: null,
  severity: 'MEDIUM',
  score: 5,
  published: null,
  fixedVersions,
  kev: null,
  epss: null,
  ...over,
});

let nextId = 1;
const component = (name: string, version: string, vulns: ComponentVuln[], over: Partial<InventoryComponent> = {}) =>
  ({
    id: nextId++,
    projectId: 1,
    projectName: 'app',
    name,
    version,
    ecosystem: 'npm',
    packageKey: `npm:${name}`,
    vulns,
    ...over,
  }) as unknown as InventoryComponent;

const KEV = { dateAdded: '2024-01-01', dueDate: null, ransomware: false };

describe('aggregateUpgrades targets', () => {
  test('the primary target is the lowest fixed version in the current major that clears the most CVEs', () => {
    const { upgrades } = aggregateUpgrades([
      component('lodash', '4.17.15', [vuln('A', ['4.17.19']), vuln('B', ['4.17.21', '5.0.0']), vuln('C', ['3.0.0'])]),
    ]);
    expect(upgrades).toHaveLength(1);
    expect(upgrades[0]).toMatchObject({ name: 'lodash', version: '4.17.15' });
    expect(upgrades[0].sameMajor).toEqual({ version: '4.17.21', clears: ['A', 'B'] });
    expect(upgrades[0].clearsAll).toBeNull();
    expect(upgrades[0].remaining).toEqual(['C']);
  });

  test('a CVE fixed only in a later major is cleared by the major bump, not the primary target', () => {
    const { upgrades } = aggregateUpgrades([component('x', '1.2.0', [vuln('A', ['1.2.5']), vuln('B', ['2.0.1'])])]);
    expect(upgrades[0].sameMajor).toEqual({ version: '1.2.5', clears: ['A'] });
    expect(upgrades[0].clearsAll).toEqual({ version: '2.0.1', clears: ['A', 'B'] });
    expect(upgrades[0].remaining).toEqual(['B']);
  });

  test('with no fix in the current major only the major bump exists and it is the ranked target', () => {
    const { upgrades } = aggregateUpgrades([component('x', '1.2.0', [vuln('A', ['2.0.0'])])]);
    expect(upgrades[0].sameMajor).toBeNull();
    expect(upgrades[0].clearsAll).toEqual({ version: '2.0.0', clears: ['A'] });
    expect(upgrades[0].remaining).toEqual([]);
  });

  test('fixed versions at or below the current version and prereleases are not targets', () => {
    const { upgrades } = aggregateUpgrades([component('x', '1.2.0', [vuln('A', ['1.1.0', '1.3.0-rc.1', '1.4.0'])])]);
    expect(upgrades[0].sameMajor).toEqual({ version: '1.4.0', clears: ['A'] });
  });

  test('packages with no fixed version are listed separately', () => {
    const { upgrades, unfixed } = aggregateUpgrades([
      component('dead', '1.0.0', [vuln('A', []), vuln('B', [])]),
      component('ok', '1.0.0', [vuln('C', ['1.0.1'])]),
    ]);
    expect(upgrades.map((u) => u.name)).toEqual(['ok']);
    expect(unfixed).toHaveLength(1);
    expect(unfixed[0]).toMatchObject({ name: 'dead', version: '1.0.0', vulnerabilities: ['A', 'B'] });
  });

  test('components without vulnerabilities are ignored', () => {
    expect(aggregateUpgrades([component('clean', '1.0.0', [])])).toEqual({ upgrades: [], unfixed: [] });
  });
});

describe('aggregateUpgrades projects and ranking', () => {
  test('one row per package version, with every affected project once', () => {
    const { upgrades } = aggregateUpgrades([
      component('x', '1.0.0', [vuln('A', ['1.0.1'])], { projectId: 1, projectName: 'a' }),
      component('x', '1.0.0', [vuln('A', ['1.0.1'])], { projectId: 2, projectName: 'b' }),
      component('x', '1.0.0', [vuln('A', ['1.0.1'])], { projectId: 2, projectName: 'b' }),
      component('x', '0.9.0', [vuln('A', ['1.0.1'])], { projectId: 3, projectName: 'c' }),
    ]);
    expect(upgrades).toHaveLength(2);
    const row = upgrades.find((u) => u.version === '1.0.0')!;
    expect(row.projects).toEqual([
      { id: 1, name: 'a' },
      { id: 2, name: 'b' },
    ]);
  });

  test('ranks by summed risk with KEV above EPSS above CVSS, numbering from 1', () => {
    const { upgrades } = aggregateUpgrades([
      component('high', '1.0.0', [vuln('H1', ['1.0.1'], { severity: 'HIGH', score: 8 })]),
      component('critical', '1.0.0', [vuln('C1', ['1.0.1'], { severity: 'CRITICAL', score: 9.8 })]),
      component('likely', '1.0.0', [vuln('E1', ['1.0.1'], { epss: { score: 0.4, percentile: 0.9 } })]),
      component('exploited', '1.0.0', [vuln('K1', ['1.0.1'], { severity: 'LOW', score: 2, kev: KEV })]),
    ]);
    expect(upgrades.map((u) => [u.rank, u.name])).toEqual([
      [1, 'exploited'],
      [2, 'likely'],
      [3, 'critical'],
      [4, 'high'],
    ]);
  });

  test('clearing several CVEs adds their risk, so a package with more fixes can outrank a single worse one', () => {
    const { upgrades } = aggregateUpgrades([
      component('one', '1.0.0', [vuln('C1', ['1.0.1'], { severity: 'CRITICAL', score: 9.8 })]),
      component('three', '1.0.0', [vuln('M1', ['1.0.1']), vuln('M2', ['1.0.1']), vuln('M3', ['1.0.1'])]),
    ]);
    expect(upgrades.map((u) => u.name)).toEqual(['three', 'one']);
  });

  test('only the CVEs the primary target clears count toward risk', () => {
    const { upgrades } = aggregateUpgrades([
      component('partial', '1.0.0', [vuln('A', ['1.0.1']), vuln('B', ['2.0.0'], { kev: KEV })]),
      component('plain', '1.0.0', [vuln('C', ['1.0.1'], { severity: 'HIGH', score: 8 })]),
    ]);
    expect(upgrades[0].name).toBe('plain');
    expect(upgrades.find((u) => u.name === 'partial')!.risk.kev).toBe(0);
  });

  test('equal risk breaks ties by package name', () => {
    const { upgrades } = aggregateUpgrades([
      component('b', '1.0.0', [vuln('X', ['1.0.1'])]),
      component('a', '1.0.0', [vuln('Y', ['1.0.1'])]),
    ]);
    expect(upgrades.map((u) => u.name)).toEqual(['a', 'b']);
  });
});

describe('aggregateUpgrades dependency paths', () => {
  test('a transitive package reports its parents and the path from a direct dependency', () => {
    const top = component('top', '1.0.0', []);
    const mid = component('mid', '1.0.0', []);
    const leaf = component('leaf', '1.0.0', [vuln('A', ['1.0.1'])]);
    const { upgrades } = aggregateUpgrades(
      [top, mid, leaf],
      [
        {
          edges: [
            { parentId: top.id, childId: mid.id },
            { parentId: mid.id, childId: leaf.id },
          ],
          directIds: [top.id],
        },
      ],
    );
    expect(upgrades[0]).toMatchObject({
      direct: false,
      parents: [{ name: 'mid', version: '1.0.0' }],
      path: [
        { name: 'top', version: '1.0.0' },
        { name: 'mid', version: '1.0.0' },
        { name: 'leaf', version: '1.0.0' },
      ],
    });
  });

  test('a direct dependency has no path, and without a graph nothing is claimed', () => {
    const direct = component('d', '1.0.0', [vuln('A', ['1.0.1'])]);
    const [withGraph] = aggregateUpgrades([direct], [{ edges: [], directIds: [direct.id] }]).upgrades;
    expect(withGraph).toMatchObject({ direct: true, parents: [], path: null });
    const [bare] = aggregateUpgrades([direct]).upgrades;
    expect(bare).toMatchObject({ direct: null, parents: [], path: null });
  });
});

describe('aggregateUpgrades on stored inventory', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
  });
  afterEach(() => close());

  const POSTCSS: OsvVuln = {
    id: 'GHSA-postcss',
    aliases: ['CVE-2099-1'],
    summary: 'postcss issue',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [
      {
        package: { ecosystem: 'npm', name: 'postcss', purl: 'pkg:npm/postcss' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '8.5.30' }] }],
      },
    ],
  };

  test('finds the upgrade, the fixed version and the parent of a transitive postcss', async () => {
    const { projectId } = await ingestSbom(db, fixture('github-spdx-graph.json'), { project: 'app' });
    await enrich(db, {
      ...enrichOptions({ vulns: { 'pkg:npm/postcss@8.5.23': ['GHSA-postcss'] }, osvVulns: { 'GHSA-postcss': POSTCSS } }),
      logger: { info() {}, warn() {}, error() {} },
    });
    const graph = (await getDependencyGraph(db, projectId))!;
    const { upgrades, unfixed } = aggregateUpgrades(await loadComponents(db), [graph]);
    expect(unfixed).toEqual([]);
    expect(upgrades).toHaveLength(1);
    expect(upgrades[0]).toMatchObject({
      name: 'postcss',
      version: '8.5.23',
      sameMajor: { version: '8.5.30', clears: ['GHSA-postcss'] },
      direct: false,
      parents: [{ name: 'next', version: '16.4.1' }],
      projects: [{ id: projectId, name: 'app' }],
    });
    expect(upgrades[0].path?.map((p) => p.name)).toEqual(['next', 'postcss']);
  });
});
