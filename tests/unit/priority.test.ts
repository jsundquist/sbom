import { describe, expect, test } from 'vitest';
import { comparePriority, type PriorityInput } from '@/lib/priority';
import { aggregateVulnerabilities, type ComponentVuln, type InventoryComponent } from '@/server/inventory';

const v = (over: Partial<PriorityInput> = {}): PriorityInput => ({ kev: null, epss: null, severity: 'MEDIUM', score: 5, ...over });
const KEV = { dateAdded: '2024-01-01' };
const sorted = (list: PriorityInput[]) => [...list].sort(comparePriority);

describe('comparePriority', () => {
  test('a known exploited vulnerability outranks everything else', () => {
    const exploitedLow = v({ kev: KEV, severity: 'LOW', score: 2 });
    const criticalHighEpss = v({ severity: 'CRITICAL', score: 9.8, epss: { score: 0.97 } });
    expect(sorted([criticalHighEpss, exploitedLow])[0]).toBe(exploitedLow);
  });

  test('without KEV, higher EPSS wins even against higher CVSS', () => {
    const likely = v({ severity: 'MEDIUM', score: 5, epss: { score: 0.4 } });
    const severe = v({ severity: 'CRITICAL', score: 9.8, epss: { score: 0.001 } });
    expect(sorted([severe, likely])[0]).toBe(likely);
  });

  test('a scored EPSS of zero is not below an unscored CVE; both fall through to severity', () => {
    const unscored = v({ severity: 'HIGH', score: 8, epss: null });
    const zero = v({ severity: 'LOW', score: 3, epss: { score: 0 } });
    expect(sorted([zero, unscored])[0]).toBe(unscored);
  });

  test('ties on KEV and EPSS fall back to severity, then CVSS score', () => {
    const high = v({ severity: 'HIGH', score: 7.5 });
    const higher = v({ severity: 'HIGH', score: 8.8 });
    const critical = v({ severity: 'CRITICAL', score: null });
    expect(sorted([high, critical, higher])).toEqual([critical, higher, high]);
  });

  test('is a consistent order for equal inputs', () => {
    expect(comparePriority(v(), v())).toBe(0);
  });
});

describe('aggregateVulnerabilities ranking', () => {
  const vuln = (id: string, over: Partial<ComponentVuln> = {}): ComponentVuln => ({
    id,
    cve: id,
    aliases: [],
    summary: null,
    severity: 'MEDIUM',
    score: 5,
    published: null,
    fixedVersions: [],
    kev: null,
    epss: null,
    ...over,
  });
  const component = (vulns: ComponentVuln[]) =>
    ({
      id: 1,
      projectId: 1,
      projectName: 'app',
      name: 'pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      packageKey: 'npm:pkg',
      vulns,
    }) as unknown as InventoryComponent;

  test('orders by priority, numbers rows from 1 and breaks ties by id', () => {
    const list = aggregateVulnerabilities([
      component([
        vuln('B-2', { severity: 'CRITICAL', score: 9.8 }),
        vuln('A-1', { severity: 'CRITICAL', score: 9.8 }),
        vuln('C-3', { severity: 'LOW', score: 2, kev: { dateAdded: '2024-01-01', dueDate: null, ransomware: false } }),
        vuln('D-4', { epss: { score: 0.5, percentile: 0.9 } }),
      ]),
    ]);
    expect(list.map((v) => [v.rank, v.id])).toEqual([
      [1, 'C-3'],
      [2, 'D-4'],
      [3, 'A-1'],
      [4, 'B-2'],
    ]);
  });
});
