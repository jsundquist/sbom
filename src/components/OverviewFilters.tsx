'use client';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import type { OverviewFilter } from '@/lib/params';

const KEYS = ['kind', 'tag', 'repository'] as const;
const ANY = '';

interface Facets {
  kinds: string[];
  tags: string[];
  repositories: string[];
}

/** Narrows the overview by kind, tag and repository. The URL is the state, so a filtered view is a bookmark (ADR 0004). */
export function OverviewFilters({ facets, active }: { facets: Facets; active: OverviewFilter }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const set = (key: (typeof KEYS)[number], value: string) => {
    const next = new URLSearchParams(params);
    if (value === ANY) {
      next.delete(key);
    } else {
      next.set(key, value);
    }
    const query = next.toString();
    router.push(query ? `${pathname}?${query}` : pathname);
  };
  const field = (key: (typeof KEYS)[number], label: string, options: string[]) => (
    <TextField
      select
      size="small"
      label={label}
      value={active[key] ?? ANY}
      onChange={(e) => set(key, e.target.value)}
      sx={{ minWidth: 180 }}
      slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
    >
      <MenuItem value={ANY}>Any</MenuItem>
      {options.map((o) => (
        <MenuItem key={o} value={o}>
          {o}
        </MenuItem>
      ))}
    </TextField>
  );
  return (
    <Stack direction="row" spacing={2} useFlexGap sx={{ mb: 2, flexWrap: 'wrap', alignItems: 'center' }} role="group" aria-label="Filters">
      {field('kind', 'Kind', facets.kinds)}
      {field('tag', 'Tag', facets.tags)}
      {field('repository', 'Repository', facets.repositories)}
      {KEYS.some((k) => active[k]) && (
        <Button size="small" onClick={() => router.push(pathname)}>
          Clear filters
        </Button>
      )}
    </Stack>
  );
}
