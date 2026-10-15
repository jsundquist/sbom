'use client';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import type { GridColDef } from '@mui/x-data-grid';
import type { PackageVersionUsage } from '@/server/inventory';
import { OkChip, OutdatedChip, SeverityChip } from './chips';
import { Grid } from './grid';
import { AppLink } from './Links';
import { projectHref } from '@/lib/routes';

const columns: GridColDef<PackageVersionUsage>[] = [
  { field: 'version', headerName: 'Version', flex: 1, minWidth: 110, valueGetter: (v) => v ?? '(unknown)' },
  {
    field: 'projects',
    headerName: 'Used by',
    flex: 2,
    minWidth: 200,
    sortable: false,
    valueGetter: (_v, row) => row.projects.map((p) => p.name).join(' '),
    renderCell: ({ row }) => (
      <Stack direction="row" spacing={1.5} useFlexGap sx={{ flexWrap: 'wrap' }}>
        {row.projects.map((p) => (
          <AppLink key={p.id} href={projectHref(p.id)}>
            {p.name}
          </AppLink>
        ))}
      </Stack>
    ),
  },
  {
    field: 'vulnCount',
    headerName: 'Vulnerabilities',
    width: 170,
    renderCell: ({ row }) =>
      row.maxSeverity ? (
        <Stack direction="row" spacing={0.5} sx={{ alignItems: 'center' }}>
          <SeverityChip severity={row.maxSeverity} />
          <Typography variant="body2" color="text.secondary">
            {row.vulnCount}
          </Typography>
        </Stack>
      ) : (
        <OkChip label="None known" />
      ),
  },
  { field: 'fixVersion', headerName: 'Fixed in', width: 110, valueGetter: (v) => v ?? '' },
  { field: 'outdated', headerName: 'Update', width: 150, renderCell: ({ row }) => <OutdatedChip outdated={row.outdated} /> },
];

export function PackageVersionsTable({ versions }: { versions: PackageVersionUsage[] }) {
  return (
    <Grid label="Versions in use" getRowId={(r) => r.version ?? ''} rows={versions} columns={columns} hideFooter={versions.length <= 25} />
  );
}
