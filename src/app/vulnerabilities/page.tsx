import { getDb } from '@/db';
import { listVulnerabilities } from '@/server/inventory';
import { PageHeader } from '@/components/PageHeader';
import { VulnerabilitiesGrid } from '@/components/VulnerabilitiesGrid';

export const dynamic = 'force-dynamic';

export default async function VulnerabilitiesPage() {
  const vulnerabilities = await listVulnerabilities(getDb());
  return (
    <>
      <PageHeader title="Vulnerabilities" subtitle="Known vulnerabilities (from OSV.dev) affecting packages in the latest SBOMs" />
      <VulnerabilitiesGrid vulnerabilities={vulnerabilities} />
    </>
  );
}
