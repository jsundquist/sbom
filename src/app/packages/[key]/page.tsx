import { notFound } from 'next/navigation';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { getDb } from '@/db';
import { getPackage } from '@/server/inventory';
import { OutdatedChip, SeverityCounts } from '@/components/chips';
import { PackageVersionsTable } from '@/components/PackageVersionsTable';
import { PageHeader } from '@/components/PageHeader';
import { StatTile } from '@/components/StatTile';
import { VulnerabilitiesGrid } from '@/components/VulnerabilitiesGrid';
import { emptySeverityCounts } from '@/server/inventory';

export const dynamic = 'force-dynamic';

export default async function PackagePage({ params }: { params: Promise<{ key: string }> }) {
  const pkg = await getPackage(getDb(), decodeURIComponent((await params).key));
  if (!pkg) {
    notFound();
  }
  const counts = emptySeverityCounts();
  for (const v of pkg.vulnerabilities) {
    counts[v.severity]++;
  }

  return (
    <>
      <PageHeader
        title={pkg.name}
        crumbs={[{ href: '/packages', label: 'Packages' }]}
        subtitle={[pkg.ecosystem, pkg.purl, pkg.licenses.join(', ')].filter(Boolean).join(' · ')}
      />
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <StatTile label="Latest version" value={pkg.latestVersion ?? '—'}>
            <Box sx={{ mt: 1 }}>
              <OutdatedChip outdated={pkg.outdated} latest={pkg.latestVersion} />
            </Box>
          </StatTile>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <StatTile label="Applications" value={pkg.projectCount} hint={`${pkg.versions.length} distinct versions in use`} />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <StatTile label="Vulnerabilities" value={pkg.vulnCount}>
            <Box sx={{ mt: 1 }}>
              <SeverityCounts counts={counts} />
            </Box>
          </StatTile>
        </Grid>
      </Grid>
      <Typography variant="h6" component="h2" sx={{ mb: 1 }}>
        Versions in use
      </Typography>
      <Box sx={{ mb: 3 }}>
        <PackageVersionsTable versions={pkg.versions} />
      </Box>
      {pkg.vulnerabilities.length > 0 && (
        <>
          <Typography variant="h6" component="h2" sx={{ mb: 1 }}>
            Vulnerabilities
          </Typography>
          <VulnerabilitiesGrid vulnerabilities={pkg.vulnerabilities} />
        </>
      )}
    </>
  );
}
