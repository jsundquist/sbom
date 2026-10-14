import path from 'node:path';

function list(value) {
  return (value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function num(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function loadConfig(env = process.env) {
  return {
    port: num(env.PORT, 3000),
    databasePath: env.DATABASE_PATH || path.resolve('data', 'sbom.db'),
    // Bearer tokens accepted by the upload API (used by the GitHub Action).
    uploadTokens: list(env.UPLOAD_TOKENS),
    // Optional HTTP basic auth protecting the dashboard and read APIs.
    dashboardUser: env.DASHBOARD_USER || '',
    dashboardPassword: env.DASHBOARD_PASSWORD || '',
    maxUploadSize: env.MAX_UPLOAD_SIZE || '50mb',
    // Number of SBOM uploads kept per project (older ones are pruned).
    historyLimit: num(env.SBOM_HISTORY_LIMIT, 20),
    // Enrichment (CVE + latest version lookups).
    enrichmentEnabled: env.ENRICHMENT_ENABLED !== 'false',
    enrichIntervalMinutes: num(env.ENRICH_INTERVAL_MINUTES, 60),
    vulnTtlHours: num(env.VULN_TTL_HOURS, 12),
    latestTtlHours: num(env.LATEST_TTL_HOURS, 24),
    osvApiUrl: env.OSV_API_URL || 'https://api.osv.dev',
    depsDevApiUrl: env.DEPS_DEV_API_URL || 'https://api.deps.dev',
  };
}
