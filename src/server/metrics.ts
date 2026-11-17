// Prometheus text exposition for GET /metrics. Labels are project and severity only (no package or CVE labels), so cardinality
// is bounded by the number of Projects.
import { eq } from 'drizzle-orm';
import type { Db } from '@/db';
import { feedSyncs } from '@/db/schema';
import { SEVERITIES } from '@/lib/severity';
import { WORKER_FEED } from '@/lib/worker-heartbeat';
import { listProjects, type ProjectSummary } from '@/server/inventory';

export { WORKER_FEED };

const escapeLabel = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');

export function formatMetrics(projects: ProjectSummary[], workerLastSuccess: Date | null, now: Date): string {
  const lines: string[] = [];
  const family = (name: string, help: string, samples: [string, number][]) => {
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`);
    for (const [labels, value] of samples) {
      lines.push(`${name}${labels} ${value}`);
    }
  };
  const p = (x: ProjectSummary) => `project="${escapeLabel(x.name)}"`;

  family(
    'sbom_vulnerabilities',
    'Distinct vulnerabilities in the latest SBOM of a project, by severity.',
    projects.flatMap((x) => SEVERITIES.map((s): [string, number] => [`{${p(x)},severity="${s}"}`, x.stats.severity[s]])),
  );
  family(
    'sbom_exploited_vulnerabilities',
    'Vulnerabilities known to be exploited (CISA KEV) in the latest SBOM of a project.',
    projects.map((x): [string, number] => [`{${p(x)}}`, x.stats.exploited]),
  );
  family(
    'sbom_age_seconds',
    'Seconds since the latest SBOM of a project was uploaded.',
    projects.flatMap((x): [string, number][] =>
      x.latest ? [[`{${p(x)}}`, Math.max(0, Math.floor((now.getTime() - new Date(x.latest.uploadedAt).getTime()) / 1000))]] : [],
    ),
  );
  family(
    'sbom_stale',
    '1 when the latest SBOM is older than STALE_AFTER_DAYS.',
    projects.map((x): [string, number] => [`{${p(x)}}`, x.stale ? 1 : 0]),
  );
  family(
    'sbom_worker_last_success_timestamp_seconds',
    'Unix time of the last enrichment run that finished without errors; absent until the first one.',
    workerLastSuccess ? [['', Math.floor(workerLastSuccess.getTime() / 1000)]] : [],
  );
  return `${lines.join('\n')}\n`;
}

export async function getMetrics(db: Db, now = new Date()): Promise<string> {
  const [projects, [worker]] = await Promise.all([
    listProjects(db),
    db.select({ syncedAt: feedSyncs.syncedAt }).from(feedSyncs).where(eq(feedSyncs.name, WORKER_FEED)),
  ]);
  return formatMetrics(projects, worker?.syncedAt ?? null, now);
}
