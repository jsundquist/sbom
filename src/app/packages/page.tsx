import { getDb } from '@/db';
import { requireOwnerPage } from '@/server/auth';
import { AccessGate } from '@/components/AccessGate';
import { listPackages } from '@/server/inventory';
import { PackagesGrid } from '@/components/PackagesGrid';
import { PageHeader } from '@/components/PageHeader';

export const dynamic = 'force-dynamic';

export default async function PackagesPage() {
  const gate = await requireOwnerPage();
  if (gate) {
    return <AccessGate gate={gate} />;
  }
  const packages = await listPackages(getDb());
  return (
    <>
      <PageHeader title="Packages" subtitle="Every package used across the latest SBOM of each application" />
      <PackagesGrid packages={packages} />
    </>
  );
}
