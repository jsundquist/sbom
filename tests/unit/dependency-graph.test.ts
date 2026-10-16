import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { schema, setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { GET as getDependencies } from '@/app/api/v1/projects/[id]/dependencies/route';
import { ingestSbom } from '@/server/ingest';
import { getDependencyGraph, type DependencyGraph } from '@/server/inventory';
import { createTestDb, fixture } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  resetEnv();
});
afterEach(() => close());

/** Edges as "parent -> child" names; the subject itself is "(app)". */
function readable(graph: DependencyGraph) {
  const label = new Map(graph.components.map((c) => [c.id, `${c.name}@${c.version}`]));
  return {
    edges: new Set(graph.edges.map((e) => `${label.get(e.parentId)} -> ${label.get(e.childId)}`)),
    direct: graph.directIds && new Set(graph.directIds.map((id) => label.get(id))),
  };
}

describe('dependency graph storage', () => {
  test('stores the edges of an uploaded SBOM and reads them back with the direct dependencies', async () => {
    const { projectId } = await ingestSbom(db, fixture('github-spdx-graph.json'), { project: 'app' });
    const graph = (await getDependencyGraph(db, projectId))!;
    const { edges, direct } = readable(graph);
    expect(edges).toContain('next@16.4.1 -> postcss@8.5.23');
    expect(edges).toContain('vite@8.3.4 -> postcss@8.5.29');
    expect(edges.size).toBe(6);
    expect(direct).toEqual(new Set(['vitest@5.0.4', 'next@16.4.1', '@mui/material-nextjs@9.5.0']));
  });

  test('an SBOM without relationships has no edges and unknown direct dependencies', async () => {
    const { projectId } = await ingestSbom(db, fixture('cyclonedx.json'), { project: 'plain' });
    const graph = (await getDependencyGraph(db, projectId))!;
    expect(graph.edges).toEqual([]);
    expect(graph.directIds).toBeNull();
    expect(graph.components.length).toBeGreaterThan(0);
  });

  test('each upload keeps its own edges, and pruned uploads take theirs with them', async () => {
    const first = await ingestSbom(db, fixture('github-spdx-graph.json'), { project: 'app' }, { historyLimit: 1 });
    const second = await ingestSbom(db, fixture('syft-cyclonedx-graph.json'), { project: 'app' }, { historyLimit: 1 });
    expect(await getDependencyGraph(db, first.projectId, first.sbomId)).toBeNull();
    const graph = (await getDependencyGraph(db, second.projectId))!;
    expect(graph.sbomId).toBe(second.sbomId);
    expect(readable(graph).edges).toContain('vitest@5.0.4 -> vite@8.3.4');
    // The first upload's rows are gone, not just hidden.
    expect(await db.select().from(schema.componentEdges)).toHaveLength(graph.edges.length);
  });

  test('unknown projects and SBOMs are not found', async () => {
    const { projectId } = await ingestSbom(db, fixture('github-spdx-graph.json'), { project: 'app' });
    expect(await getDependencyGraph(db, projectId + 99)).toBeNull();
    expect(await getDependencyGraph(db, projectId, 99999)).toBeNull();
  });
});

describe('GET /api/v1/projects/[id]/dependencies', () => {
  const call = (id: string, query = '') =>
    getDependencies(new Request(`http://dash.test/api/v1/projects/${id}/dependencies${query}`), { params: Promise.resolve({ id }) });

  test('returns the graph as JSON and 404s for unknown projects or SBOMs', async () => {
    const { projectId } = await ingestSbom(db, fixture('github-spdx-graph.json'), { project: 'app' });
    const ok = await call(String(projectId));
    expect(ok.status).toBe(200);
    const body = await ok.json();
    expect(body.edges).toHaveLength(6);
    expect(body.directIds).toHaveLength(3);
    expect((await call('9999')).status).toBe(404);
    expect((await call(String(projectId), '?sbom=9999')).status).toBe(404);
    expect((await call('abc')).status).toBe(404);
  });
});
