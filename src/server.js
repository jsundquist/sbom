import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { createApp } from './app.js';
import { Enricher } from './enrich/index.js';

const config = loadConfig();
const db = openDatabase(config.databasePath);
const enricher = config.enrichmentEnabled ? new Enricher(db, config) : null;
const app = createApp({ db, config, enricher });

if (!config.uploadTokens.length) {
  console.warn('UPLOAD_TOKENS is not set: the upload API will reject all requests.');
}

const server = app.listen(config.port, () => {
  console.log(`SBOM dashboard listening on http://localhost:${config.port}`);
});

if (enricher) {
  enricher.trigger();
  const timer = setInterval(() => enricher.trigger(), config.enrichIntervalMinutes * 60e3);
  timer.unref();
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
