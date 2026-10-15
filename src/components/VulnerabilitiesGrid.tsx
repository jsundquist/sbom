'use client';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import type { GridColDef } from '@mui/x-data-grid';
import type { VulnerabilitySummary } from '@/server/inventory';
import { SEVERITY_RANK } from '@/lib/severity';
import { SeverityChip } from './chips';
import { DateTime } from './DateTime';
import { Grid } from './grid';
import { AppLink } from './Links';
import { packageHref, projectHref, vulnHref } from '@/lib/routes';

const columns: GridColDef<VulnerabilitySummary>[] = [
  {
    field: 'id',
    headerName: 'Vulnerability',
    width: 200,
    valueGetter: (_v, row) => `${row.cve ?? ''} ${row.id}`,
    renderCell: ({ row }) => (
      <Box>
        <AppLink href={vulnHref(row.id)}>{row.cve ?? row.id}</AppLink>
        {row.cve && row.cve !== row.id && (
          <Typography variant="caption" color="text.secondary" component="div">
            {row.id}
          </Typography>
        )}
      </Box>
    ),
  },
  {
    field: 'severity',
    headerName: 'Severity',
    width: 150,
    valueGetter: (_v, row) => SEVERITY_RANK[row.severity] * 100 + (row.score ?? 0),
    renderCell: ({ row }) => <SeverityChip severity={row.severity} score={row.score} />,
  },
  { field: 'summary', headerName: 'Summary', flex: 2, minWidth: 240, valueGetter: (v) => v ?? '' },
  {
    field: 'affected',
    headerName: 'Affected package',
    flex: 1.3,
    minWidth: 200,
    valueGetter: (_v, row) => row.affected.map((a) => `${a.name}@${a.version}`).join(' '),
    renderCell: ({ row }) => (
      <Stack spacing={0.25}>
        {row.affected.map((a) => (
          <Box key={`${a.packageKey}@${a.version}`}>
            <AppLink href={packageHref(a.packageKey)}>{a.name}</AppLink>{' '}
            <Typography variant="body2" component="span" color="text.secondary">
              {a.version}
              {a.fixVersion ? ` → ${a.fixVersion}` : ''}
            </Typography>
          </Box>
        ))}
      </Stack>
    ),
  },
  {
    field: 'projects',
    headerName: 'Applications',
    flex: 1,
    minWidth: 160,
    valueGetter: (_v, row) => row.projects.map((p) => p.name).join(' '),
    renderCell: ({ row }) => (
      <Stack spacing={0.25}>
        {row.projects.map((p) => (
          <AppLink key={p.id} href={projectHref(p.id)}>
            {p.name}
          </AppLink>
        ))}
      </Stack>
    ),
  },
  {
    field: 'published',
    headerName: 'Published',
    width: 120,
    valueGetter: (v) => v ?? '',
    renderCell: ({ row }) => <DateTime value={row.published} dateOnly />,
  },
];

export function VulnerabilitiesGrid({ vulnerabilities, hideProjects = false }: { vulnerabilities: VulnerabilitySummary[]; hideProjects?: boolean }) {
  return (
    <Grid
      label="Vulnerabilities"
      rows={vulnerabilities}
      columns={hideProjects ? columns.filter((c) => c.field !== 'projects') : columns}
      initialState={{ sorting: { sortModel: [{ field: 'severity', sort: 'desc' }] } }}
    />
  );
}
