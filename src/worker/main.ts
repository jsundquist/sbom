// Long-running worker: enriches package data whenever an SBOM is uploaded
// (Postgres LISTEN/NOTIFY) and on a polling interval for periodic re-scans.
import { Client } from 'pg';
import { closeDb, getDb } from '@/db';
import { env } from '@/lib/env';
import { SBOM_UPLOADED_CHANNEL } from '@/lib/channels';
import { enrich } from './enrich';

const config = env();
const db = getDb();

/** Kubernetes sends SIGKILL after terminationGracePeriodSeconds (default 30s); finish or give up before that. */
const SHUTDOWN_GRACE_MS = 25_000;

let running = false;
let rerun = false;
let stopping = false;
let current: Promise<void> | undefined;
let listener: Client | undefined;

function run() {
  if (stopping) {
    return;
  }
  if (running) {
    rerun = true;
    return;
  }
  running = true;
  current = runLoop();
}

async function runLoop() {
  try {
    do {
      rerun = false;
      const started = Date.now();
      const stats = await enrich(db, {
        osvApiUrl: config.OSV_API_URL,
        depsDevApiUrl: config.DEPS_DEV_API_URL,
        vulnTtlHours: config.VULN_TTL_HOURS,
        latestTtlHours: config.LATEST_TTL_HOURS,
        scorecardTtlHours: config.SCORECARD_TTL_HOURS,
        kevUrl: config.KEV_URL,
        kevTtlHours: config.KEV_TTL_HOURS,
        epssUrl: config.EPSS_API_URL,
        epssTtlHours: config.EPSS_TTL_HOURS,
        logger: console,
      });
      if (stats.versionsScanned || stats.packagesChecked || stats.feedsSynced || stats.errors) {
        console.info(`[worker] ${JSON.stringify({ ...stats, ms: Date.now() - started })}`);
      }
    } while (rerun && !stopping);
  } catch (err) {
    console.error('[worker] enrichment failed:', err);
  } finally {
    running = false;
  }
}

async function listen() {
  const client = new Client({ connectionString: config.DATABASE_URL });
  listener = client;
  client.on('error', (err) => {
    console.error('[worker] listener connection lost:', err.message);
    if (!stopping) {
      setTimeout(() => void listen(), 5000);
    }
  });
  try {
    await client.connect();
    await client.query(`LISTEN ${SBOM_UPLOADED_CHANNEL}`);
    client.on('notification', () => run());
    console.info(`[worker] listening for uploads on "${SBOM_UPLOADED_CHANNEL}"`);
  } catch (err) {
    console.error('[worker] could not LISTEN, relying on polling:', (err as Error).message);
    if (!stopping) {
      setTimeout(() => void listen(), 5000);
    }
  }
}

await listen();
run();
console.info(`[worker] polling every ${config.WORKER_POLL_SECONDS}s`);
const timer = setInterval(() => run(), config.WORKER_POLL_SECONDS * 1000);

async function shutdown() {
  if (stopping) {
    return;
  }
  stopping = true;
  clearInterval(timer);
  await listener?.end().catch(() => {});
  if (current) {
    console.info('[worker] shutting down, waiting for the current enrichment run');
    const grace = new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), SHUTDOWN_GRACE_MS).unref());
    if ((await Promise.race([current, grace])) === 'timeout') {
      console.warn('[worker] enrichment still running after the grace period, exiting anyway');
    }
  }
  await closeDb();
  process.exit(0);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => void shutdown());
}
