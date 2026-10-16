// Turns a dependency graph (a DAG that may contain cycles and shared nodes) into a tree to display, and answers
// "which paths pull this package in". Pure so the display rules can be tested without a database or UI.

export interface DependencyTreeInput {
  nodes: { id: number; label: string; vulnerable: boolean }[];
  /** `parentId` depends on `childId`. */
  edges: { parentId: number; childId: number }[];
  /** Components the application depends on directly, or null when the SBOM does not say. */
  directIds: number[] | null;
}

export interface TreeItem {
  /** Unique per occurrence: a shared dependency appears under several parents. */
  itemId: string;
  componentId: number;
  children: TreeItem[];
  /** The component is already expanded elsewhere (or is its own ancestor), so this entry is a leaf. */
  repeated: boolean;
  /** Some package below this one is vulnerable. */
  vulnerableBelow: boolean;
}

interface Index {
  label: Map<number, string>;
  vulnerable: Set<number>;
  children: Map<number, number[]>;
  parents: Map<number, number[]>;
}

function index(g: DependencyTreeInput): Index {
  const label = new Map(g.nodes.map((n) => [n.id, n.label]));
  const byLabel = (a: number, b: number) => (label.get(a) ?? '').localeCompare(label.get(b) ?? '') || a - b;
  const children = new Map<number, number[]>();
  const parents = new Map<number, number[]>();
  for (const e of g.edges) {
    if (!label.has(e.parentId) || !label.has(e.childId)) {
      continue;
    }
    children.set(e.parentId, [...(children.get(e.parentId) ?? []), e.childId]);
    parents.set(e.childId, [...(parents.get(e.childId) ?? []), e.parentId]);
  }
  for (const map of [children, parents]) {
    for (const [k, v] of map) {
      map.set(k, [...new Set(v)].sort(byLabel));
    }
  }
  return { label, vulnerable: new Set(g.nodes.filter((n) => n.vulnerable).map((n) => n.id)), children, parents };
}

const sortedByLabel = (ix: Index, ids: Iterable<number>) =>
  [...ids].sort((a, b) => (ix.label.get(a) ?? '').localeCompare(ix.label.get(b) ?? '') || a - b);

function rootsOf(g: DependencyTreeInput, ix: Index): number[] {
  if (g.directIds) {
    return sortedByLabel(
      ix,
      g.directIds.filter((id) => ix.label.has(id)),
    );
  }
  const roots = sortedByLabel(
    ix,
    g.nodes.map((n) => n.id).filter((id) => !ix.parents.has(id)),
  );
  // Members of a cycle that nothing outside the cycle depends on have a parent but are still unreachable.
  const reached = new Set<number>();
  const mark = (id: number) => {
    const stack = [id];
    while (stack.length) {
      const next = stack.pop()!;
      if (!reached.has(next)) {
        reached.add(next);
        stack.push(...(ix.children.get(next) ?? []));
      }
    }
  };
  roots.forEach(mark);
  for (const id of sortedByLabel(
    ix,
    g.nodes.map((n) => n.id),
  )) {
    if (!reached.has(id)) {
      roots.push(id);
      mark(id);
    }
  }
  return roots;
}

/** Where the tree starts: the direct dependencies, or the components nothing depends on when those are unknown. */
export function rootIds(g: DependencyTreeInput): number[] {
  return rootsOf(g, index(g));
}

/** Components that have a vulnerable package strictly below them. */
function withVulnerableDescendant(ix: Index): Set<number> {
  const found = new Set<number>();
  const stack = [...ix.vulnerable].flatMap((id) => ix.parents.get(id) ?? []);
  while (stack.length) {
    const id = stack.pop()!;
    if (!found.has(id)) {
      found.add(id);
      stack.push(...(ix.parents.get(id) ?? []));
    }
  }
  return found;
}

export function buildTreeItems(g: DependencyTreeInput, { onlyVulnerable = false } = {}): TreeItem[] {
  const ix = index(g);
  const above = withVulnerableDescendant(ix);
  const visible = (id: number) => !onlyVulnerable || ix.vulnerable.has(id) || above.has(id);
  const expanded = new Set<number>();
  const onPath = new Set<number>();

  const build = (id: number, parentItemId: string | null): TreeItem => {
    const itemId = parentItemId ? `${parentItemId}/${id}` : String(id);
    const base = { itemId, componentId: id, vulnerableBelow: above.has(id) };
    if (expanded.has(id) || onPath.has(id)) {
      return { ...base, children: [], repeated: true };
    }
    expanded.add(id);
    onPath.add(id);
    const children = (ix.children.get(id) ?? []).filter(visible).map((child) => build(child, itemId));
    onPath.delete(id);
    return { ...base, children, repeated: false };
  };

  return rootsOf(g, ix)
    .filter(visible)
    .map((id) => build(id, null));
}

/** Every simple path from a root down to `targetId` (a root is its own path), up to `limit` paths. */
export function pathsTo(g: DependencyTreeInput, targetId: number, { limit = 50 } = {}): number[][] {
  const ix = index(g);
  if (!ix.label.has(targetId)) {
    return [];
  }
  const roots = new Set(rootsOf(g, ix));
  const paths: number[][] = [];
  const upward: number[] = [];
  const walk = (id: number) => {
    if (paths.length >= limit) {
      return;
    }
    upward.push(id);
    if (roots.has(id)) {
      paths.push([...upward].reverse());
    }
    for (const parent of ix.parents.get(id) ?? []) {
      if (!upward.includes(parent)) {
        walk(parent);
      }
    }
    upward.pop();
  };
  walk(targetId);
  return paths;
}
