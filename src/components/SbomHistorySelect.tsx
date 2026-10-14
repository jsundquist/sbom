'use client';
import { usePathname, useRouter } from 'next/navigation';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import type { SbomInfo } from '@/server/inventory';

export function SbomHistorySelect({ history, selected, latestId }: { history: SbomInfo[]; selected: number; latestId: number | null }) {
  const router = useRouter();
  const pathname = usePathname();
  return (
    <TextField
      select
      size="small"
      label="SBOM upload"
      value={selected}
      onChange={(e) => {
        const id = Number(e.target.value);
        router.push(id === latestId ? pathname : `${pathname}?sbom=${id}`);
      }}
      sx={{ minWidth: 260 }}
    >
      {history.map((h) => (
        <MenuItem key={h.id} value={h.id}>
          {[h.version ?? 'unversioned', h.uploadedAt.slice(0, 16).replace('T', ' ')].join(' — ')}
          {h.id === latestId ? ' (latest)' : ''}
        </MenuItem>
      ))}
    </TextField>
  );
}
