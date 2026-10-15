'use client';
import { useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import MenuItem from '@mui/material/MenuItem';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import type { GridColDef } from '@mui/x-data-grid';
import type { InventoryComponent } from '@/server/inventory';
import { SEVERITY_RANK } from '@/lib/severity';
import { UPDATE_RANK } from '@/lib/version';
import { OkChip, OutdatedChip, PendingChip, SeverityChip } from './chips';
import { Grid } from './grid';
import { AppLink } from './Links';
import { packageHref } from '@/lib/routes';

type Filter = 'all' | 'vulnerable' | 'outdated';

const columns: GridColDef<InventoryComponent>[] = [
  {
    field: 'name',
    headerName: 'Package',
    flex: 2,
    minWidth: 200,
    renderCell: ({ row }) => (
      <Box sx={{ minWidth: 0 }}>
        <AppLink href={packageHref(row.packageKey ?? `name:${row.name}`)}>{row.name}</AppLink>
        {row.purl && (
          <Typography variant="caption" color="text.secondary" component="div" sx={{ wordBreak: 'break-all' }}>
            {row.purl}
          </Typography>
        )}
      </Box>
    ),
  },
  { field: 'version', headerName: 'Version', flex: 1, minWidth: 100 },
  { field: 'ecosystem', headerName: 'Ecosystem', width: 110, valueGetter: (v) => v ?? '—' },
  {
    field: 'vulns',
    headerName: 'Vulnerabilities',
    flex: 1.2,
    minWidth: 170,
    valueGetter: (_v, row) =>
      row.maxSeverity ? SEVERITY_RANK[row.maxSeverity] * 1000 + row.vulns.length : row.vulnStatus === 'scanned' ? 0 : -1,
    renderCell: ({ row }) =>
      row.maxSeverity ? (
        <Stack direction="row" spacing={0.5} sx={{ alignItems: 'center' }}>
          <SeverityChip severity={row.maxSeverity} />
          <Typography variant="body2" color="text.secondary">
            {row.vulns.length} {row.vulns.length === 1 ? 'CVE' : 'CVEs'}
          </Typography>
        </Stack>
      ) : row.vulnStatus === 'scanned' ? (
        <OkChip label="None known" />
      ) : row.vulnStatus === 'pending' ? (
        <PendingChip />
      ) : (
        <Typography variant="body2" color="text.secondary">
          Not scanned
        </Typography>
      ),
  },
  { field: 'fixVersion', headerName: 'Fixed in', width: 110, valueGetter: (v) => v ?? '' },
  { field: 'latestVersion', headerName: 'Latest', width: 110, valueGetter: (v) => v ?? '' },
  {
    field: 'outdated',
    headerName: 'Update',
    width: 150,
    valueGetter: (v: InventoryComponent['outdated']) => (v ? UPDATE_RANK[v] : 0),
    renderCell: ({ row }) =>
      row.versionStatus === 'pending' ? (
        <PendingChip label="Checking…" />
      ) : (
        <OutdatedChip outdated={row.outdated} latest={row.latestVersion} />
      ),
  },
  { field: 'licenses', headerName: 'License', flex: 1, minWidth: 110, valueGetter: (v) => v ?? '' },
];

export function ComponentsGrid({ components }: { components: InventoryComponent[] }) {
  const [filter, setFilter] = useState<Filter>('all');
  const [ecosystem, setEcosystem] = useState('');
  const ecosystems = useMemo(() => [...new Set(components.map((c) => c.ecosystem ?? 'unknown'))].sort(), [components]);
  const rows = useMemo(
    () =>
      components.filter(
        (c) =>
          (filter === 'all' || (filter === 'vulnerable' ? c.vulns.length > 0 : c.outdated !== null)) &&
          (!ecosystem || (c.ecosystem ?? 'unknown') === ecosystem),
      ),
    [components, filter, ecosystem],
  );
  const vulnerable = components.filter((c) => c.vulns.length).length;
  const outdated = components.filter((c) => c.outdated).length;

  return (
    <Box>
      <Stack direction="row" spacing={2} useFlexGap sx={{ mb: 1.5, flexWrap: 'wrap', alignItems: 'center' }}>
        <ToggleButtonGroup size="small" exclusive value={filter} onChange={(_e, v) => v && setFilter(v)} aria-label="Filter packages">
          <ToggleButton value="all">All ({components.length})</ToggleButton>
          <ToggleButton value="vulnerable">Vulnerable ({vulnerable})</ToggleButton>
          <ToggleButton value="outdated">Outdated ({outdated})</ToggleButton>
        </ToggleButtonGroup>
        <TextField
          select
          size="small"
          label="Ecosystem"
          value={ecosystem}
          onChange={(e) => setEcosystem(e.target.value)}
          sx={{ minWidth: 160 }}
          slotProps={{ inputLabel: { shrink: true }, select: { displayEmpty: true } }}
        >
          <MenuItem value="">All ecosystems</MenuItem>
          {ecosystems.map((e) => (
            <MenuItem key={e} value={e}>
              {e}
            </MenuItem>
          ))}
        </TextField>
      </Stack>
      <Grid label="Packages" rows={rows} columns={columns} initialState={{ sorting: { sortModel: [{ field: 'vulns', sort: 'desc' }] } }} />
    </Box>
  );
}
