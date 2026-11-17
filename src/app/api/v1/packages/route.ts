import { getDb } from '@/db';
import { parsePage, parsePackageFilter } from '@/lib/params';
import { jsonError, listJson } from '@/server/api';
import { requireOwner } from '@/server/auth';
import { listPackagesPage } from '@/server/inventory';

export async function GET(req: Request) {
  const denied = await requireOwner(req);
  if (denied) {
    return denied;
  }
  const sp = new URL(req.url).searchParams;
  const filter = parsePackageFilter(sp);
  if (!filter.ok) {
    return jsonError(400, filter.error);
  }
  const page = parsePage(sp);
  if (!page.ok) {
    return jsonError(400, page.error);
  }
  return listJson(await listPackagesPage(getDb(), filter.value, page.value));
}
