'use client';
import { useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import type { GridColDef } from '@mui/x-data-grid';
import type { PackageSummary } from '@/server/inventory';
import { SEVERITY_RANK } from '@/lib/severity';
import { UPDATE_RANK } from '@/lib/version';
import { OutdatedChip, SeverityChip } from './chips';
import { Grid } from './grid';
import { AppLink } from './Links';
import { packageHref } from '@/lib/routes';

const columns: GridColDef<PackageSummary>[] = [
  {
    field: 'name',
    headerName: 'Package',
    flex: 2,
    minWidth: 200,
    renderCell: ({ row }) => <AppLink href={packageHref(row.key)}>{row.name}</AppLink>,
  },
  { field: 'ecosystem', headerName: 'Ecosystem', width: 110, valueGetter: (v) => v ?? '—' },
  {
    field: 'versions',
    headerName: 'Versions in use',
    flex: 1.5,
    minWidth: 160,
    sortable: false,
    valueGetter: (_v, row) => row.versions.map((v) => v.version ?? '?').join(', '),
  },
  { field: 'latestVersion', headerName: 'Latest', width: 110, valueGetter: (v) => v ?? '' },
  { field: 'projectCount', headerName: 'Applications', type: 'number', width: 110 },
  {
    field: 'vulnCount',
    headerName: 'Vulnerabilities',
    flex: 1,
    minWidth: 170,
    valueGetter: (_v, row) => (row.maxSeverity ? SEVERITY_RANK[row.maxSeverity] * 1000 + row.vulnCount : 0),
    renderCell: ({ row }) =>
      row.maxSeverity ? (
        <Stack direction="row" spacing={0.5} sx={{ alignItems: 'center' }}>
          <SeverityChip severity={row.maxSeverity} />
          <Typography variant="body2" color="text.secondary">
            {row.vulnCount}
          </Typography>
        </Stack>
      ) : null,
  },
  {
    field: 'outdated',
    headerName: 'Update',
    width: 150,
    valueGetter: (v: PackageSummary['outdated']) => (v ? UPDATE_RANK[v] : 0),
    renderCell: ({ row }) => <OutdatedChip outdated={row.outdated} latest={row.latestVersion} />,
  },
];

type Filter = 'all' | 'vulnerable' | 'outdated' | 'shared';

export function PackagesGrid({ packages }: { packages: PackageSummary[] }) {
  const [filter, setFilter] = useState<Filter>('all');
  const rows = useMemo(
    () =>
      packages.filter((p) =>
        filter === 'vulnerable' ? p.vulnCount > 0 : filter === 'outdated' ? !!p.outdated : filter === 'shared' ? p.projectCount > 1 : true,
      ),
    [packages, filter],
  );
  return (
    <Box>
      <ToggleButtonGroup
        size="small"
        exclusive
        value={filter}
        onChange={(_e, v) => v && setFilter(v)}
        sx={{ mb: 1.5, flexWrap: 'wrap' }}
        aria-label="Filter packages"
      >
        <ToggleButton value="all">All ({packages.length})</ToggleButton>
        <ToggleButton value="vulnerable">Vulnerable ({packages.filter((p) => p.vulnCount).length})</ToggleButton>
        <ToggleButton value="outdated">Outdated ({packages.filter((p) => p.outdated).length})</ToggleButton>
        <ToggleButton value="shared">Used by 2+ apps ({packages.filter((p) => p.projectCount > 1).length})</ToggleButton>
      </ToggleButtonGroup>
      <Grid
        label="Packages"
        getRowId={(r) => r.key}
        rows={rows}
        columns={columns}
        initialState={{ sorting: { sortModel: [{ field: 'vulnCount', sort: 'desc' }] } }}
      />
    </Box>
  );
}
