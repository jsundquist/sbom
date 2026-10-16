import {
  type AnyPgColumn,
  boolean,
  date,
  foreignKey,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  real,
  serial,
  text,
  timestamp,
} from 'drizzle-orm/pg-core';

export const severityEnum = pgEnum('severity', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

const timestamps = {
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
};

/** An application or library that uploads SBOMs. */
export const projects = pgTable('projects', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  repository: text('repository'),
  latestSbomId: integer('latest_sbom_id').references((): AnyPgColumn => sboms.id, { onDelete: 'set null' }),
  ...timestamps,
});

/** One uploaded SBOM document. */
export const sboms = pgTable(
  'sboms',
  {
    id: serial('id').primaryKey(),
    projectId: integer('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    version: text('version'),
    ref: text('ref'),
    commitSha: text('commit_sha'),
    format: text('format').notNull(),
    specVersion: text('spec_version'),
    componentCount: integer('component_count').notNull(),
    document: jsonb('document').notNull(),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('sboms_project_idx').on(t.projectId, t.uploadedAt)],
);

/** A package listed in an SBOM. */
export const components = pgTable(
  'components',
  {
    id: serial('id').primaryKey(),
    sbomId: integer('sbom_id')
      .notNull()
      .references(() => sboms.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    version: text('version'),
    purl: text('purl'),
    ecosystem: text('ecosystem'),
    packageKey: text('package_key'),
    type: text('type'),
    licenses: text('licenses'),
    supplier: text('supplier'),
  },
  (t) => [index('components_sbom_idx').on(t.sbomId), index('components_package_idx').on(t.packageKey, t.version)],
);

/**
 * "parent depends on child" within one SBOM. A null parent means the SBOM's subject depends on the child directly, so a
 * graph with no null-parent rows does not say which components are direct.
 */
export const componentEdges = pgTable(
  'component_edges',
  {
    id: serial('id').primaryKey(),
    sbomId: integer('sbom_id')
      .notNull()
      .references(() => sboms.id, { onDelete: 'cascade' }),
    parentId: integer('parent_id').references(() => components.id, { onDelete: 'cascade' }),
    childId: integer('child_id')
      .notNull()
      .references(() => components.id, { onDelete: 'cascade' }),
  },
  (t) => [index('component_edges_sbom_idx').on(t.sbomId)],
);

/** A distinct package (version independent), e.g. "npm:lodash". Enriched with the latest release. */
export const packages = pgTable('packages', {
  key: text('key').primaryKey(),
  ecosystem: text('ecosystem').notNull(),
  namespace: text('namespace'),
  name: text('name').notNull(),
  latestVersion: text('latest_version'),
  latestCheckedAt: timestamp('latest_checked_at', { withTimezone: true }),
  latestError: text('latest_error'),
});

/** A package version in use. `vulnsCheckedAt` drives the vulnerability scan queue. */
export const packageVersions = pgTable(
  'package_versions',
  {
    packageKey: text('package_key')
      .notNull()
      .references(() => packages.key, { onDelete: 'cascade' }),
    version: text('version').notNull(),
    vulnsCheckedAt: timestamp('vulns_checked_at', { withTimezone: true }),
    vulnsError: text('vulns_error'),
  },
  (t) => [primaryKey({ columns: [t.packageKey, t.version] }), index('package_versions_checked_idx').on(t.vulnsCheckedAt)],
);

export type Reference = { type: string; url: string };

/** A vulnerability record from OSV.dev (GHSA, CVE, PYSEC, ...). */
export const vulnerabilities = pgTable('vulnerabilities', {
  id: text('id').primaryKey(),
  aliases: jsonb('aliases').$type<string[]>().notNull().default([]),
  summary: text('summary'),
  details: text('details'),
  severity: severityEnum('severity').notNull().default('UNKNOWN'),
  score: real('score'),
  vector: text('vector'),
  published: timestamp('published', { withTimezone: true }),
  modified: timestamp('modified', { withTimezone: true }),
  references: jsonb('references').$type<Reference[]>().notNull().default([]),
  fetchedAt: timestamp('fetched_at', { withTimezone: true }).notNull().defaultNow(),
});

/** Which vulnerabilities affect which package version, and the versions that fix them. */
export const versionVulnerabilities = pgTable(
  'version_vulnerabilities',
  {
    packageKey: text('package_key').notNull(),
    version: text('version').notNull(),
    vulnerabilityId: text('vulnerability_id')
      .notNull()
      .references(() => vulnerabilities.id, { onDelete: 'cascade' }),
    fixedVersions: jsonb('fixed_versions').$type<string[]>().notNull().default([]),
  },
  (t) => [
    primaryKey({ columns: [t.packageKey, t.version, t.vulnerabilityId] }),
    foreignKey({ columns: [t.packageKey, t.version], foreignColumns: [packageVersions.packageKey, packageVersions.version] }).onDelete(
      'cascade',
    ),
  ],
);

export type Severity = (typeof severityEnum.enumValues)[number];

/** An entry of the CISA Known Exploited Vulnerabilities catalog, keyed by CVE id. */
export const kevEntries = pgTable('kev_entries', {
  cveId: text('cve_id').primaryKey(),
  vendor: text('vendor'),
  product: text('product'),
  name: text('name'),
  dateAdded: date('date_added', { mode: 'string' }).notNull(),
  dueDate: date('due_date', { mode: 'string' }),
  knownRansomwareUse: boolean('known_ransomware_use').notNull().default(false),
});

/** Bookkeeping for worker jobs that download whole feeds (one row per feed). */
export const feedSyncs = pgTable('feed_syncs', {
  name: text('name').primaryKey(),
  /** Last successful sync; null until the first one succeeds. */
  syncedAt: timestamp('synced_at', { withTimezone: true }),
  /** Last attempt, successful or not; used to back off after failures. */
  attemptedAt: timestamp('attempted_at', { withTimezone: true }).notNull().defaultNow(),
  error: text('error'),
});

/** FIRST EPSS score for a CVE. A null score means the CVE was looked up but has none yet. */
export const epssScores = pgTable('epss_scores', {
  cveId: text('cve_id').primaryKey(),
  score: real('score'),
  percentile: real('percentile'),
  modelDate: date('model_date', { mode: 'string' }),
  fetchedAt: timestamp('fetched_at', { withTimezone: true }).notNull().defaultNow(),
});
