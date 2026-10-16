import { notFound } from 'next/navigation';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import DownloadIcon from '@mui/icons-material/Download';
import { getDb } from '@/db';
import { parseIdOrNull } from '@/lib/params';
import { getDependencyGraph, getProject } from '@/server/inventory';
import { ComponentsGrid } from '@/components/ComponentsGrid';
import { PendingChip, SeverityCounts } from '@/components/chips';
import { DateTime } from '@/components/DateTime';
import { DependencyTree } from '@/components/DependencyTree';
import { ProjectTabs } from '@/components/ProjectTabs';
import { PageHeader } from '@/components/PageHeader';
import { SbomHistorySelect } from '@/components/SbomHistorySelect';
import { StatTile } from '@/components/StatTile';

export const dynamic = 'force-dynamic';

export default async function ProjectPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ sbom?: string; tab?: string }>;
}) {
  const id = parseIdOrNull((await params).id);
  const { sbom: sbomParam, tab } = await searchParams;
  const activeTab = tab === 'dependencies' ? 'dependencies' : 'packages';
  const sbomId = sbomParam ? parseIdOrNull(sbomParam) : undefined;
  const project = id && sbomId !== null ? await getProject(getDb(), id, sbomId) : null;
  if (!project) {
    notFound();
  }

  const graph = activeTab === 'dependencies' && project.sbomId ? await getDependencyGraph(getDb(), project.id, project.sbomId) : null;
  const sbom = project.history.find((h) => h.id === project.sbomId);
  const { stats } = project;
  return (
    <>
      <PageHeader
        title={project.name}
        crumbs={[{ href: '/projects', label: 'Applications' }]}
        subtitle={
          <Box component="span">
            {[
              project.repository,
              sbom?.version && `version ${sbom.version}`,
              sbom?.ref && sbom.ref.replace(/^refs\/(heads|tags)\//, '') !== sbom.version && sbom.ref.replace(/^refs\/(heads|tags)\//, ''),
              sbom?.commit?.slice(0, 7),
              sbom && `${sbom.format} ${sbom.specVersion ?? ''}`.trim(),
            ]
              .filter(Boolean)
              .join(' · ')}
            {sbom && (
              <>
                {' · uploaded '}
                <DateTime value={sbom.uploadedAt} />
              </>
            )}
          </Box>
        }
        actions={
          sbom && (
            <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
              {project.history.length > 1 && (
                <SbomHistorySelect history={project.history} selected={sbom.id} latestId={project.latest?.id ?? null} />
              )}
              <Button variant="outlined" startIcon={<DownloadIcon />} href={`/api/v1/sboms/${sbom.id}`}>
                Download SBOM
              </Button>
            </Stack>
          )
        }
      />
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatTile
            label="Packages"
            value={stats.components}
            hint={`${project.uploadCount} ${project.uploadCount === 1 ? 'upload' : 'uploads'} stored`}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 5 }}>
          <StatTile label="Vulnerabilities" value={stats.vulnerabilities} hint={`in ${stats.vulnerableComponents} packages`}>
            <Box sx={{ mt: 1 }}>
              <SeverityCounts counts={stats.severity} />
            </Box>
          </StatTile>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
          <StatTile
            label="Outdated packages"
            value={stats.outdatedComponents}
            hint={`${stats.outdated.major} major · ${stats.outdated.minor} minor · ${stats.outdated.patch} patch`}
          >
            {stats.pending > 0 && (
              <Box sx={{ mt: 1 }}>
                <PendingChip label={`${stats.pending} packages pending`} />
              </Box>
            )}
          </StatTile>
        </Grid>
      </Grid>
      <ProjectTabs value={activeTab} />
      {activeTab === 'dependencies' ? (
        graph ? (
          <DependencyTree graph={graph} />
        ) : (
          <Alert severity="info">No SBOM has been uploaded for this application yet.</Alert>
        )
      ) : (
        <ComponentsGrid components={project.components} />
      )}
    </>
  );
}
