import crypto from 'node:crypto';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { ingestSbom, garbageCollect } from './ingest.js';
import { SbomParseError } from './sbom/parse.js';
import {
  loadComponents,
  summarize,
  listProjects,
  getProject,
  listPackages,
  listVulnerabilities,
  getVulnerability,
} from './inventory.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function createApp({ db, config, enricher }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);

  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // --- Upload API (bearer token) -------------------------------------------------
  const requireUploadToken = (req, res, next) => {
    if (!config.uploadTokens.length) {
      return res.status(503).json({ error: 'Uploads are disabled: set UPLOAD_TOKENS on the server' });
    }
    const header = req.get('authorization') || '';
    const token = header.replace(/^Bearer\s+/i, '');
    if (!token || !config.uploadTokens.some((t) => safeEqual(t, token))) {
      return res.status(401).json({ error: 'Invalid or missing upload token' });
    }
    next();
  };

  const rawJson = express.text({ type: () => true, limit: config.maxUploadSize });

  app.post('/api/v1/sboms', requireUploadToken, rawJson, (req, res, next) => {
    let text = typeof req.body === 'string' ? req.body : '';
    let document;
    try {
      document = JSON.parse(text);
    } catch {
      return res.status(400).json({ error: 'Request body must be a JSON SBOM document' });
    }
    const pick = (q, h) => (req.query[q] ?? req.get(h) ?? '').toString().trim() || undefined;
    const meta = {
      project: pick('project', 'x-sbom-project'),
      version: pick('version', 'x-sbom-version'),
      ref: pick('ref', 'x-sbom-ref'),
      commit: pick('commit', 'x-sbom-commit'),
      repository: pick('repository', 'x-sbom-repository'),
    };
    try {
      const result = ingestSbom(db, document, meta, { historyLimit: config.historyLimit, rawText: text });
      garbageCollect(db);
      enricher?.trigger();
      const base = `${req.protocol}://${req.get('host')}`;
      res.status(201).json({ ...result, url: `${base}/#/projects/${result.projectId}` });
    } catch (err) {
      if (err instanceof SbomParseError || err.status === 400) return res.status(400).json({ error: err.message });
      next(err);
    }
  });

  app.post('/api/v1/enrich', requireUploadToken, async (req, res) => {
    const wait = req.query.wait === 'true';
    const run = enricher?.trigger({ force: req.query.force === 'true' });
    if (wait && run) await run;
    res.status(202).json({ triggered: Boolean(enricher), lastRun: enricher?.lastRun ?? null });
  });

  app.delete('/api/v1/projects/:id', requireUploadToken, (req, res) => {
    const project = getProject(db, req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    db.prepare('DELETE FROM projects WHERE id = ?').run(project.id);
    garbageCollect(db);
    res.status(204).end();
  });

  // --- Dashboard (optional basic auth) ------------------------------------------------
  if (config.dashboardUser && config.dashboardPassword) {
    app.use((req, res, next) => {
      const [scheme, encoded] = (req.get('authorization') || '').split(' ');
      if (scheme === 'Basic' && encoded) {
        const decoded = Buffer.from(encoded, 'base64').toString();
        const idx = decoded.indexOf(':');
        if (safeEqual(decoded.slice(0, idx), config.dashboardUser) && safeEqual(decoded.slice(idx + 1), config.dashboardPassword)) {
          return next();
        }
      }
      res.set('WWW-Authenticate', 'Basic realm="SBOM Dashboard"').status(401).send('Authentication required');
    });
  }

  app.get('/api/v1/summary', (req, res) => {
    const components = loadComponents(db);
    const packages = listPackages(components);
    const projects = db.prepare('SELECT COUNT(*) AS n FROM projects').get().n;
    const recent = db
      .prepare(
        `SELECT s.id, s.version, s.ref, s.uploaded_at AS uploadedAt, s.component_count AS componentCount, p.id AS projectId, p.name AS projectName
         FROM sboms s JOIN projects p ON p.id = s.project_id ORDER BY s.uploaded_at DESC, s.id DESC LIMIT 10`,
      )
      .all();
    res.json({
      projects,
      packages: packages.length,
      vulnerablePackages: packages.filter((p) => p.vulnCount).length,
      outdatedPackages: packages.filter((p) => p.outdated).length,
      stats: summarize(components),
      recentUploads: recent,
      enrichment: { enabled: config.enrichmentEnabled, running: Boolean(enricher?.running), lastRun: enricher?.lastRun ?? null },
    });
  });

  app.get('/api/v1/projects', (req, res) => res.json(listProjects(db)));

  app.get('/api/v1/projects/:id', (req, res) => {
    const project = getProject(db, req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const sbomId = req.query.sbom ? Number(req.query.sbom) : project.latest?.id;
    if (sbomId && !project.history.some((h) => h.id === sbomId)) return res.status(404).json({ error: 'SBOM not found' });
    const components = sbomId ? loadComponents(db, [sbomId]) : [];
    res.json({ ...project, sbomId, stats: summarize(components), components });
  });

  app.get('/api/v1/sboms/:id/download', (req, res) => {
    const row = db
      .prepare('SELECT s.raw, s.version, p.name FROM sboms s JOIN projects p ON p.id = s.project_id WHERE s.id = ?')
      .get(Number(req.params.id));
    if (!row?.raw) return res.status(404).json({ error: 'SBOM not found' });
    const filename = `${row.name}-${row.version || req.params.id}.sbom.json`.replace(/[^\w.@-]+/g, '_');
    res.set('content-type', 'application/json');
    res.set('content-disposition', `attachment; filename="${filename}"`);
    res.send(zlib.gunzipSync(row.raw));
  });

  app.get('/api/v1/packages', (req, res) => res.json(listPackages(loadComponents(db))));

  app.get('/api/v1/packages/:key', (req, res) => {
    const components = loadComponents(db).filter((c) => (c.packageKey || `name:${c.name}`) === req.params.key);
    if (!components.length) return res.status(404).json({ error: 'Package not found' });
    const [pkg] = listPackages(components);
    res.json({ ...pkg, purl: components[0].purl, vulnerabilities: listVulnerabilities(components) });
  });

  app.get('/api/v1/vulnerabilities', (req, res) => res.json(listVulnerabilities(loadComponents(db))));

  app.get('/api/v1/vulnerabilities/:id', (req, res) => {
    const vuln = getVulnerability(db, req.params.id);
    if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
    const usage = listVulnerabilities(loadComponents(db)).find((v) => v.id === vuln.id);
    res.json({ ...vuln, affected: usage?.affected || [], projects: usage?.projects || [] });
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.use(express.static(PUBLIC_DIR));

  app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: `SBOM exceeds ${config.maxUploadSize}` });
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
