import { getDb } from '@/db';
import { listPackages } from '@/server/inventory';
import { PackagesGrid } from '@/components/PackagesGrid';
import { PageHeader } from '@/components/PageHeader';

export const dynamic = 'force-dynamic';

export default async function PackagesPage() {
  const packages = await listPackages(getDb());
  return (
    <>
      <PageHeader title="Packages" subtitle="Every package used across the latest SBOM of each application" />
      <PackagesGrid packages={packages} />
    </>
  );
}
