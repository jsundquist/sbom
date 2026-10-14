import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  repository TEXT,
  latest_sbom_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sboms (
  id INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version TEXT,
  ref TEXT,
  commit_sha TEXT,
  format TEXT NOT NULL,
  spec_version TEXT,
  component_count INTEGER NOT NULL,
  uploaded_at TEXT NOT NULL,
  raw BLOB
);
CREATE INDEX IF NOT EXISTS sboms_project ON sboms(project_id, uploaded_at);

CREATE TABLE IF NOT EXISTS components (
  id INTEGER PRIMARY KEY,
  sbom_id INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  version TEXT,
  purl TEXT,
  ecosystem TEXT,
  package_key TEXT,
  type TEXT,
  licenses TEXT,
  supplier TEXT
);
CREATE INDEX IF NOT EXISTS components_sbom ON components(sbom_id);
CREATE INDEX IF NOT EXISTS components_pkg ON components(package_key, version);

-- One row per distinct package (version independent).
CREATE TABLE IF NOT EXISTS packages (
  key TEXT PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  namespace TEXT,
  name TEXT NOT NULL,
  latest_version TEXT,
  latest_checked_at TEXT,
  latest_error TEXT
);

-- One row per package version in use; tracks the last vulnerability scan.
CREATE TABLE IF NOT EXISTS package_versions (
  package_key TEXT NOT NULL REFERENCES packages(key) ON DELETE CASCADE,
  version TEXT NOT NULL,
  vulns_checked_at TEXT,
  vulns_error TEXT,
  PRIMARY KEY (package_key, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id TEXT PRIMARY KEY,
  aliases TEXT NOT NULL DEFAULT '[]',
  summary TEXT,
  details TEXT,
  severity TEXT NOT NULL DEFAULT 'UNKNOWN',
  score REAL,
  vector TEXT,
  published TEXT,
  modified TEXT,
  refs TEXT NOT NULL DEFAULT '[]',
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS version_vulns (
  package_key TEXT NOT NULL,
  version TEXT NOT NULL,
  vuln_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  fixed_versions TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (package_key, version, vuln_id),
  FOREIGN KEY (package_key, version) REFERENCES package_versions(package_key, version) ON DELETE CASCADE
);
`;

export function openDatabase(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON;');
  if (file !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
  db.exec(SCHEMA);
  return db;
}

export function transaction(db, fn) {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}
