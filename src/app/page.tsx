import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { getDb } from '@/db';
import { getOverview } from '@/server/inventory';
import { requestOrigin } from '@/server/origin';
import { KevChip, PendingChip, SeverityCounts } from '@/components/chips';
import { ProjectRiskChart, SeverityBarChart } from '@/components/charts';
import { DateTime } from '@/components/DateTime';
import { GettingStarted } from '@/components/GettingStarted';
import { AppLink } from '@/components/Links';
import { projectHref } from '@/lib/routes';
import { PageHeader } from '@/components/PageHeader';
import { ProjectsGrid } from '@/components/ProjectsGrid';
import { StatTile } from '@/components/StatTile';

export const dynamic = 'force-dynamic';

export default async function OverviewPage() {
  const data = await getOverview(getDb());
  if (!data.projectCount) {
    return (
      <>
        <PageHeader title="Overview" />
        <GettingStarted origin={await requestOrigin()} />
      </>
    );
  }
  const { stats } = data;
  return (
    <>
      <PageHeader title="Overview" subtitle={`Latest SBOM of each of ${data.projectCount} applications`} />
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatTile label="Applications" value={data.projectCount} hint={`${stats.components.toLocaleString()} package references`} />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatTile label="Unique packages" value={data.packageCount.toLocaleString()} hint={`${data.vulnerablePackages} with known CVEs`} />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatTile label="Vulnerabilities" value={stats.vulnerabilities}>
            <Box sx={{ mt: 1 }}>
              {stats.pending ? <PendingChip label={`${stats.pending} packages pending scan`} /> : <SeverityCounts counts={stats.severity} />}
            </Box>
            {stats.exploited > 0 && (
              <Box sx={{ mt: 1 }}>
                <AppLink href="/vulnerabilities">
                  <KevChip count={stats.exploited} />
                </AppLink>
              </Box>
            )}
          </StatTile>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatTile
            label="Outdated packages"
            value={data.outdatedPackages}
            hint={`${stats.outdated.major} major · ${stats.outdated.minor} minor · ${stats.outdated.patch} patch (references)`}
          />
        </Grid>
      </Grid>

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, md: 5 }}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" component="h2" gutterBottom>
              Vulnerabilities by severity
            </Typography>
            <SeverityBarChart counts={stats.severity} />
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" component="h2" gutterBottom>
              Most exposed applications
            </Typography>
            <ProjectRiskChart projects={data.projects} />
          </Paper>
        </Grid>
      </Grid>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Typography variant="h6" component="h2" sx={{ mb: 1 }}>
            Applications
          </Typography>
          <ProjectsGrid projects={data.projects} />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Typography variant="h6" component="h2" sx={{ mb: 1 }}>
            Recent uploads
          </Typography>
          <Paper>
            <Stack divider={<Box sx={{ borderTop: 1, borderColor: 'divider' }} />}>
              {data.recentUploads.map((u) => (
                <Box key={u.id} sx={{ px: 2, py: 1.25 }}>
                  <AppLink href={`${projectHref(u.projectId)}?sbom=${u.id}`}>{u.projectName}</AppLink>
                  <Typography variant="body2" color="text.secondary">
                    {[...new Set([u.version, u.ref?.replace(/^refs\/(heads|tags)\//, '')].filter(Boolean))].join(' · ') || 'unversioned'} ·{' '}
                    {u.componentCount} {u.componentCount === 1 ? 'package' : 'packages'} · <DateTime value={u.uploadedAt} />
                  </Typography>
                </Box>
              ))}
            </Stack>
          </Paper>
        </Grid>
      </Grid>
    </>
  );
}
