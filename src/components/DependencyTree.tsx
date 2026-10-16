'use client';
import { createContext, forwardRef, useContext, useMemo, useState } from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import FormControlLabel from '@mui/material/FormControlLabel';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Switch from '@mui/material/Switch';
import Typography from '@mui/material/Typography';
import { RichTreeView } from '@mui/x-tree-view/RichTreeView';
import { TreeItem, type TreeItemProps } from '@mui/x-tree-view/TreeItem';
import { buildTreeItems, pathsTo, type DependencyTreeInput, type TreeItem as TreeEntry } from '@/lib/dependency-tree';
import { packageHref, vulnHref } from '@/lib/routes';
import type { DependencyGraph, InventoryComponent } from '@/server/inventory';
import { SeverityChip } from './chips';
import { AppLink } from './Links';

const PATH_LIMIT = 20;
const nameOf = (c: InventoryComponent) => `${c.name}${c.version ? `@${c.version}` : ''}`;

interface TreeNode {
  id: string;
  label: string;
  children: TreeNode[];
}

const toNode = (item: TreeEntry, label: (id: number) => string): TreeNode => ({
  id: item.itemId,
  label: label(item.componentId),
  children: item.children.map((c) => toNode(c, label)),
});

function flatten(items: TreeEntry[]): TreeEntry[] {
  return items.flatMap((i) => [i, ...flatten(i.children)]);
}

interface ItemData {
  entries: Map<string, TreeEntry>;
  components: Map<number, InventoryComponent>;
}
const ItemDataContext = createContext<ItemData>({ entries: new Map(), components: new Map() });

/** Tree row with severity and "shown above" markers. Defined once so rows are not remounted on every render. */
const DependencyItem = forwardRef<HTMLLIElement, TreeItemProps>(function DependencyItem(props, ref) {
  const { entries, components } = useContext(ItemDataContext);
  const row = entries.get(props.itemId);
  const c = row && components.get(row.componentId);
  const label = c ? (
    <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap', py: 0.25 }} useFlexGap>
      <span>{nameOf(c)}</span>
      {c.maxSeverity && <SeverityChip severity={c.maxSeverity} count={c.vulns.length} />}
      {row?.vulnerableBelow && !c.maxSeverity && <Chip size="small" variant="outlined" label="vulnerable below" />}
      {row?.repeated && <Chip size="small" variant="outlined" label="shown above" />}
    </Stack>
  ) : (
    props.label
  );
  return <TreeItem {...props} ref={ref} label={label} />;
});

export function DependencyTree({ graph }: { graph: DependencyGraph }) {
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string[]>([]);

  const byId = useMemo(() => new Map(graph.components.map((c) => [c.id, c])), [graph.components]);
  const input: DependencyTreeInput = useMemo(
    () => ({
      nodes: graph.components.map((c) => ({ id: c.id, label: nameOf(c), vulnerable: c.vulns.length > 0 })),
      edges: graph.edges,
      directIds: graph.directIds,
    }),
    [graph],
  );
  const items = useMemo(() => buildTreeItems(input, { onlyVulnerable }), [input, onlyVulnerable]);
  const itemById = useMemo(() => new Map(flatten(items).map((i) => [i.itemId, i])), [items]);
  const itemData = useMemo(() => ({ entries: itemById, components: byId }), [itemById, byId]);
  const nodes = useMemo(() => items.map((i) => toNode(i, (id) => nameOf(byId.get(id)!))), [items, byId]);

  if (!graph.edges.length && !graph.directIds) {
    return (
      <Alert severity="info">
        This SBOM does not contain dependency relationships, so there is no tree to show. SBOMs from GitHub&apos;s dependency graph or from
        Syft for lockfile-based projects include them; container and archive scans usually do not. Upload a new SBOM to see the tree.
      </Alert>
    );
  }

  const selectedItem = selected ? itemById.get(selected) : undefined;
  const component = selectedItem ? byId.get(selectedItem.componentId) : undefined;

  return (
    <>
      {!graph.directIds && (
        <Alert severity="info" sx={{ mb: 2 }}>
          This SBOM does not say which packages are direct dependencies, so the top level lists the packages nothing else depends on.
        </Alert>
      )}
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper sx={{ p: 2 }}>
            <Stack direction="row" spacing={2} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap', mb: 1 }}>
              <FormControlLabel
                control={<Switch checked={onlyVulnerable} onChange={(e) => setOnlyVulnerable(e.target.checked)} />}
                label="Only paths to vulnerable packages"
              />
              <Button
                size="small"
                onClick={() =>
                  setExpanded(
                    flatten(items)
                      .filter((i) => i.children.length)
                      .map((i) => i.itemId),
                  )
                }
              >
                Expand all
              </Button>
              <Button size="small" onClick={() => setExpanded([])}>
                Collapse all
              </Button>
            </Stack>
            {nodes.length ? (
              <ItemDataContext.Provider value={itemData}>
                <RichTreeView
                  aria-label="Dependency tree"
                  items={nodes}
                  slots={{ item: DependencyItem }}
                  expandedItems={expanded}
                  onExpandedItemsChange={(_e, ids) => setExpanded(ids)}
                  selectedItems={selected}
                  onSelectedItemsChange={(_e, id) => setSelected(id)}
                  sx={{ maxHeight: 640, overflow: 'auto' }}
                />
              </ItemDataContext.Provider>
            ) : (
              <Typography color="text.secondary" sx={{ py: 3, textAlign: 'center' }}>
                No vulnerable packages in this SBOM.
              </Typography>
            )}
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 5 }}>
          <SelectionPanel graph={graph} component={component} input={input} byId={byId} />
        </Grid>
      </Grid>
    </>
  );
}

function SelectionPanel({
  graph,
  component,
  input,
  byId,
}: {
  graph: DependencyGraph;
  component: InventoryComponent | undefined;
  input: DependencyTreeInput;
  byId: Map<number, InventoryComponent>;
}) {
  if (!component) {
    return (
      <Paper sx={{ p: 2 }}>
        <Typography color="text.secondary">
          Select a package to see why it is in this application and which versions of it are used.
        </Typography>
      </Paper>
    );
  }
  const paths = pathsTo(input, component.id, { limit: PATH_LIMIT });
  const versions = graph.components.filter((c) => c.packageKey && c.packageKey === component.packageKey);
  const parentsOf = (id: number) => graph.edges.filter((e) => e.childId === id).map((e) => byId.get(e.parentId)!);
  return (
    <Paper sx={{ p: 2 }}>
      <Typography variant="h6" component="h2">
        {component.packageKey ? <AppLink href={packageHref(component.packageKey)}>{nameOf(component)}</AppLink> : nameOf(component)}
      </Typography>
      {component.vulns.length > 0 && (
        <Box sx={{ my: 1 }}>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', mb: 0.5 }}>
            {component.vulns.map((v) => (
              <AppLink key={v.id} href={vulnHref(v.id)}>
                {v.cve ?? v.id}
              </AppLink>
            ))}
          </Stack>
          {component.fixVersion && (
            <Typography variant="body2">Upgrading this package to {component.fixVersion} fixes all of them.</Typography>
          )}
        </Box>
      )}

      <Typography variant="subtitle2" sx={{ mt: 2 }}>
        Pulled in by
      </Typography>
      {paths.length ? (
        <Stack component="ul" spacing={0.5} sx={{ m: 0, pl: 2 }}>
          {paths.map((p) => (
            <li key={p.join('>')}>
              <Typography variant="body2">{p.map((id) => nameOf(byId.get(id)!)).join(' › ')}</Typography>
            </li>
          ))}
        </Stack>
      ) : (
        <Typography variant="body2" color="text.secondary">
          No path from a top-level package was found.
        </Typography>
      )}
      {paths.length >= PATH_LIMIT && (
        <Typography variant="caption" color="text.secondary">
          Showing the first {PATH_LIMIT} paths.
        </Typography>
      )}

      {versions.length > 1 && (
        <>
          <Typography variant="subtitle2" sx={{ mt: 2 }}>
            Versions of {component.name} in this application
          </Typography>
          <Stack component="ul" spacing={0.5} sx={{ m: 0, pl: 2 }}>
            {versions.map((v) => {
              const parents = parentsOf(v.id);
              return (
                <li key={v.id}>
                  <Typography variant="body2">
                    <b>{v.version}</b>
                    {parents.length ? ` ← ${parents.map(nameOf).join(', ')}` : ' (top level)'}
                  </Typography>
                </li>
              );
            })}
          </Stack>
        </>
      )}
    </Paper>
  );
}
