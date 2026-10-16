import { describe, expect, test } from 'vitest';
import { buildTreeItems, pathsTo, rootIds, type DependencyTreeInput, type TreeItem } from '@/lib/dependency-tree';

/** Compact graph builder: names are ids' labels; "a>b" means a depends on b. */
function graph(
  nodes: Record<string, { vulnerable?: boolean }>,
  edges: string[],
  direct: string[] | null,
): DependencyTreeInput & { id: (n: string) => number; name: (id: number) => string } {
  const names = Object.keys(nodes);
  const id = (n: string) => names.indexOf(n) + 1;
  return {
    nodes: names.map((n) => ({ id: id(n), label: n, vulnerable: !!nodes[n].vulnerable })),
    edges: edges.map((e) => {
      const [a, b] = e.split('>');
      return { parentId: id(a), childId: id(b) };
    }),
    directIds: direct && direct.map(id),
    id,
    name: (i) => names[i - 1],
  };
}

/** Indented outline, repeated entries marked with "*". */
function outline(items: TreeItem[], name: (id: number) => string, depth = 0): string[] {
  return items.flatMap((i) => [
    `${'  '.repeat(depth)}${name(i.componentId)}${i.repeated ? '*' : ''}`,
    ...outline(i.children, name, depth + 1),
  ]);
}

describe('rootIds', () => {
  test('uses the direct dependencies when the SBOM lists them', () => {
    const g = graph({ app1: {}, a: {}, b: {} }, ['a>b'], ['a']);
    expect(rootIds(g).map(g.name)).toEqual(['a']);
  });

  test('falls back to components without a parent, and includes members of a cycle nobody else reaches', () => {
    const g = graph({ a: {}, b: {}, x: {}, y: {} }, ['a>b', 'x>y', 'y>x'], null);
    expect(new Set(rootIds(g).map(g.name))).toEqual(new Set(['a', 'x']));
  });
});

describe('buildTreeItems', () => {
  test('expands a shared dependency once and marks later occurrences as repeated leaves', () => {
    const g = graph({ next: {}, vite: {}, shared: {}, leaf: {} }, ['next>shared', 'vite>shared', 'shared>leaf'], ['next', 'vite']);
    expect(outline(buildTreeItems(g), g.name)).toEqual(['next', '  shared', '    leaf', 'vite', '  shared*']);
  });

  test('keeps different versions of a package apart and gives every occurrence a unique item id', () => {
    const g = graph({ next: {}, vite: {}, 'postcss@1': {}, 'postcss@2': {} }, ['next>postcss@1', 'vite>postcss@2'], ['next', 'vite']);
    const items = buildTreeItems(g);
    expect(outline(items, g.name)).toEqual(['next', '  postcss@1', 'vite', '  postcss@2']);
    const all = items.flatMap((i) => [i, ...i.children]).map((i) => i.itemId);
    expect(new Set(all).size).toBe(all.length);
  });

  test('does not loop on a dependency cycle', () => {
    const g = graph({ a: {}, b: {} }, ['a>b', 'b>a'], ['a']);
    expect(outline(buildTreeItems(g), g.name)).toEqual(['a', '  b', '    a*']);
  });

  test('can be limited to branches that lead to a vulnerable package', () => {
    const g = graph(
      { app: {}, safe: {}, risky: {}, bad: { vulnerable: true }, fine: {} },
      ['app>safe', 'app>risky', 'risky>bad', 'risky>fine', 'safe>fine'],
      ['app'],
    );
    expect(outline(buildTreeItems(g, { onlyVulnerable: true }), g.name)).toEqual(['app', '  risky', '    bad']);
  });

  test('flags items that have a vulnerable package somewhere below them', () => {
    const g = graph({ app: {}, mid: {}, bad: { vulnerable: true } }, ['app>mid', 'mid>bad'], ['app']);
    const [app] = buildTreeItems(g);
    expect(app.vulnerableBelow).toBe(true);
    expect(app.children[0].vulnerableBelow).toBe(true);
    expect(app.children[0].children[0].vulnerableBelow).toBe(false);
  });
});

describe('pathsTo', () => {
  const g = graph(
    { next: {}, vite: {}, vitest: {}, 'postcss@1': {}, 'postcss@2': {} },
    ['next>postcss@1', 'vite>postcss@2', 'vitest>vite'],
    ['next', 'vitest'],
  );

  test('lists every path from a root to the component', () => {
    expect(pathsTo(g, g.id('postcss@2')).map((p) => p.map(g.name))).toEqual([['vitest', 'vite', 'postcss@2']]);
    expect(pathsTo(g, g.id('postcss@1')).map((p) => p.map(g.name))).toEqual([['next', 'postcss@1']]);
  });

  test('a root is its own path, and an unreachable id has none', () => {
    expect(pathsTo(g, g.id('next')).map((p) => p.map(g.name))).toEqual([['next']]);
    expect(pathsTo(g, 999)).toEqual([]);
  });

  test('stops at the path limit and survives cycles', () => {
    const wide = graph({ r: {}, a: {}, b: {}, c: {}, t: {} }, ['r>a', 'r>b', 'r>c', 'a>t', 'b>t', 'c>t', 'a>r'], ['r']);
    expect(pathsTo(wide, wide.id('t'), { limit: 2 })).toHaveLength(2);
    expect(pathsTo(wide, wide.id('t'))).toHaveLength(3);
  });
});
