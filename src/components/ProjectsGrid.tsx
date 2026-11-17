'use client';
import type { GridColDef } from '@mui/x-data-grid';
import type { ProjectSummary } from '@/server/inventory';
import { SEVERITY_RANK, SEVERITIES } from '@/lib/severity';
import { PROJECT_KINDS } from '@/lib/kinds';
import { KindChip, PendingChip, SeverityCounts, StaleChip, TagChips } from './chips';
import { DateTime } from './DateTime';
import { Grid } from './grid';
import { AppLink } from './Links';
import { projectHref } from '@/lib/routes';

// Sort key: weight critical > high > medium > low > unknown.
const riskScore = (p: ProjectSummary) => SEVERITIES.reduce((sum, s) => sum + p.stats.severity[s] * 10 ** (SEVERITY_RANK[s] * 2), 0);

const columns: GridColDef<ProjectSummary>[] = [
  {
    field: 'name',
    headerName: 'Project',
    flex: 1.5,
    minWidth: 180,
    renderCell: ({ row }) => <AppLink href={projectHref(row.id)}>{row.name}</AppLink>,
  },
  // Its own column so the grid can filter and sort by it; Projects of one monorepo share a value.
  {
    field: 'repository',
    headerName: 'Repository',
    flex: 1.2,
    minWidth: 180,
    valueGetter: (_v, row) => row.repository ?? '',
  },
  {
    field: 'kind',
    headerName: 'Kind',
    type: 'singleSelect',
    valueOptions: [...PROJECT_KINDS],
    width: 120,
    renderCell: ({ row }) => <KindChip kind={row.kind} />,
  },
  {
    field: 'tags',
    headerName: 'Tags',
    flex: 1,
    minWidth: 140,
    // A string, so the toolbar's quick search and the column filter match tag text.
    valueGetter: (_v, row) => row.tags.join(' '),
    renderCell: ({ row }) => <TagChips tags={row.tags} />,
  },
  { field: 'version', headerName: 'Version', flex: 0.8, minWidth: 100, valueGetter: (_v, row) => row.latest?.version ?? '' },
  { field: 'components', headerName: 'Packages', type: 'number', width: 100, valueGetter: (_v, row) => row.stats.components },
  {
    field: 'risk',
    headerName: 'Vulnerabilities',
    flex: 2,
    minWidth: 220,
    valueGetter: (_v, row) => riskScore(row),
    renderCell: ({ row }) =>
      row.stats.pending && !row.stats.vulnerabilities ? <PendingChip /> : <SeverityCounts counts={row.stats.severity} />,
  },
  { field: 'outdated', headerName: 'Outdated', type: 'number', width: 100, valueGetter: (_v, row) => row.stats.outdatedComponents },
  {
    field: 'uploadedAt',
    headerName: 'Last upload',
    width: 180,
    valueGetter: (_v, row) => row.latest?.uploadedAt ?? '',
    renderCell: ({ row }) => <DateTime value={row.latest?.uploadedAt} />,
  },
  {
    field: 'stale',
    headerName: 'Stale',
    type: 'boolean',
    width: 100,
    valueGetter: (_v, row) => row.stale,
    renderCell: ({ row }) => (row.stale ? <StaleChip uploadedAt={row.latest?.uploadedAt} /> : null),
  },
];

export function ProjectsGrid({ projects }: { projects: ProjectSummary[] }) {
  return (
    <Grid label="Projects" rows={projects} columns={columns} initialState={{ sorting: { sortModel: [{ field: 'risk', sort: 'desc' }] } }} />
  );
}
