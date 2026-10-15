'use client';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import type { GridColDef } from '@mui/x-data-grid';
import type { ProjectSummary } from '@/server/inventory';
import { SEVERITY_RANK, SEVERITIES } from '@/lib/severity';
import { PendingChip, SeverityCounts } from './chips';
import { DateTime } from './DateTime';
import { Grid } from './grid';
import { AppLink } from './Links';
import { projectHref } from '@/lib/routes';

// Sort key: weight critical > high > medium > low > unknown.
const riskScore = (p: ProjectSummary) =>
  SEVERITIES.reduce((sum, s) => sum + p.stats.severity[s] * 10 ** (SEVERITY_RANK[s] * 2), 0);

const columns: GridColDef<ProjectSummary>[] = [
  {
    field: 'name',
    headerName: 'Application',
    flex: 1.5,
    minWidth: 180,
    renderCell: ({ row }) => (
      <Box>
        <AppLink href={projectHref(row.id)}>{row.name}</AppLink>
        {row.repository && (
          <Typography variant="caption" color="text.secondary" component="div">
            {row.repository}
          </Typography>
        )}
      </Box>
    ),
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
];

export function ProjectsGrid({ projects }: { projects: ProjectSummary[] }) {
  return <Grid label="Applications" rows={projects} columns={columns} initialState={{ sorting: { sortModel: [{ field: 'risk', sort: 'desc' }] } }} />;
}
