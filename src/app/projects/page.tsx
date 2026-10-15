import { getDb } from '@/db';
import { listProjects } from '@/server/inventory';
import { PageHeader } from '@/components/PageHeader';
import { ProjectsGrid } from '@/components/ProjectsGrid';

export const dynamic = 'force-dynamic';

export default async function ProjectsPage() {
  const projects = await listProjects(getDb());
  return (
    <>
      <PageHeader title="Applications" subtitle="Every application or library that has uploaded an SBOM" />
      <ProjectsGrid projects={projects} />
    </>
  );
}
