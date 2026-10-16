import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import type { VulnerabilitySummary } from '@/server/inventory';
import { formatEpss } from '@/lib/epss';
import { packageHref, vulnHref } from '@/lib/routes';
import { KevChip, SeverityChip } from './chips';
import { AppLink } from './Links';

/** Top of the fix-first order: known exploited, then EPSS, then severity. */
export function FixFirstList({ vulnerabilities }: { vulnerabilities: VulnerabilitySummary[] }) {
  if (!vulnerabilities.length) {
    return null;
  }
  return (
    <Paper sx={{ p: 2, mb: 2 }}>
      <Typography variant="h6" component="h2">
        Fix first
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Ranked by known exploitation (CISA KEV), then exploit probability (EPSS), then severity.
      </Typography>
      <Stack component="ol" sx={{ listStyle: 'none', m: 0, p: 0, '& > li + li': { borderTop: 1, borderColor: 'divider' } }}>
        {vulnerabilities.map((v) => {
          const pkg = v.affected[0];
          return (
            <Box
              component="li"
              key={v.id}
              sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1.5, py: 1 }}
              data-testid="fix-first-item"
            >
              <Typography sx={{ width: 28, color: 'text.secondary' }}>#{v.rank}</Typography>
              <Box sx={{ minWidth: 150 }}>
                <AppLink href={vulnHref(v.id)}>{v.cve ?? v.id}</AppLink>
              </Box>
              <SeverityChip severity={v.severity} score={v.score} />
              {v.kev && <KevChip kev={v.kev} />}
              <Typography variant="body2" color="text.secondary" sx={{ minWidth: 70 }}>
                {v.epss ? `EPSS ${formatEpss(v.epss.score)}` : 'EPSS n/a'}
              </Typography>
              {pkg && (
                <Typography variant="body2" sx={{ flex: 1, minWidth: 200 }}>
                  <AppLink href={packageHref(pkg.packageKey)}>{pkg.name}</AppLink> {pkg.version}
                  {pkg.fixVersion ? ` → ${pkg.fixVersion}` : ''}
                  {v.affected.length > 1 ? ` +${v.affected.length - 1} more` : ''}
                </Typography>
              )}
              <Typography variant="body2" color="text.secondary">
                {v.projects.map((p) => p.name).join(', ')}
              </Typography>
            </Box>
          );
        })}
      </Stack>
    </Paper>
  );
}
