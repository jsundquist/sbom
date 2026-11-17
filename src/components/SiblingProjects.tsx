'use client';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import type { ProjectSummary } from '@/server/inventory';
import { projectHref } from '@/lib/routes';
import { KindChip, PendingChip, SeverityCounts } from './chips';
import { AppLink } from './Links';

/** Other Projects built from the same repository (a monorepo's services), so they can find each other. Nothing when there are none. */
export function SiblingProjects({ repository, siblings }: { repository: string | null; siblings: ProjectSummary[] }) {
  if (!siblings.length) {
    return null;
  }
  return (
    <Paper sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6" component="h2" gutterBottom>
        Other projects in {repository}
      </Typography>
      <Stack divider={<Box sx={{ borderTop: 1, borderColor: 'divider' }} />} spacing={1}>
        {siblings.map((p) => (
          <Stack key={p.id} direction="row" spacing={1.5} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap', pt: 1 }}>
            <AppLink href={projectHref(p.id)}>{p.name}</AppLink>
            <KindChip kind={p.kind} />
            {p.stats.pending && !p.stats.vulnerabilities ? <PendingChip /> : <SeverityCounts counts={p.stats.severity} />}
          </Stack>
        ))}
      </Stack>
    </Paper>
  );
}
