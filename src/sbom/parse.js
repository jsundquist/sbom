// Normalizes CycloneDX (JSON) and SPDX (JSON) documents into a flat component list.
import { parsePurl, packageKey, displayName } from '../lib/purl.js';

export class SbomParseError extends Error {}

export function parseSbom(input) {
  let doc = input;
  // GitHub's dependency graph export wraps the SPDX document in { "sbom": ... }.
  if (doc && typeof doc === 'object' && doc.sbom && typeof doc.sbom === 'object') doc = doc.sbom;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new SbomParseError('SBOM must be a JSON object');
  if (doc.bomFormat === 'CycloneDX') return parseCycloneDx(doc);
  if (typeof doc.spdxVersion === 'string') return parseSpdx(doc);
  throw new SbomParseError('Unsupported SBOM format: expected CycloneDX JSON or SPDX JSON');
}

function normalizeComponent({ name, version, purl, type, licenses, supplier }) {
  const parsed = purl ? parsePurl(purl) : null;
  const finalVersion = version || parsed?.version || null;
  return {
    name: parsed ? displayName(parsed) : name,
    version: finalVersion,
    purl: purl || null,
    ecosystem: parsed?.type || null,
    packageKey: parsed ? packageKey(parsed) : null,
    type: type || 'library',
    licenses: licenses?.length ? [...new Set(licenses)].join(' OR ') : null,
    supplier: supplier || null,
  };
}

function dedupe(components) {
  const seen = new Map();
  for (const c of components) {
    if (!c.name) continue;
    const key = c.purl ? `${c.packageKey}@${c.version}` : `${c.name}@${c.version}`;
    if (!seen.has(key)) seen.set(key, c);
  }
  return [...seen.values()];
}

function cdxLicenses(licenses) {
  return (licenses || [])
    .map((l) => l.expression || l.license?.id || l.license?.name)
    .filter(Boolean);
}

function parseCycloneDx(doc) {
  const root = doc.metadata?.component;
  const out = [];
  const walk = (list) => {
    for (const c of list || []) {
      if (!c || typeof c !== 'object') continue;
      if (c.type !== 'file') {
        out.push(
          normalizeComponent({
            name: c.group ? `${c.group}/${c.name}` : c.name,
            version: c.version,
            purl: c.purl,
            type: c.type,
            licenses: cdxLicenses(c.licenses),
            supplier: c.supplier?.name || c.publisher || null,
          }),
        );
      }
      walk(c.components);
    }
  };
  walk(doc.components);
  return {
    format: 'CycloneDX',
    specVersion: doc.specVersion || null,
    subject: root ? { name: root.name, version: root.version || null } : null,
    components: dedupe(out.filter((c) => !(root?.purl && c.purl === root.purl))),
  };
}

function parseSpdx(doc) {
  const described = new Set(doc.documentDescribes || []);
  for (const r of doc.relationships || []) {
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === doc.SPDXID) described.add(r.relatedSpdxElement);
  }
  const out = [];
  let subject = null;
  for (const p of doc.packages || []) {
    if (described.has(p.SPDXID)) {
      subject ??= { name: p.name, version: p.versionInfo || null };
      continue;
    }
    const purlRef = (p.externalRefs || []).find((r) => r.referenceType === 'purl');
    const license = [p.licenseConcluded, p.licenseDeclared].find((l) => l && !/^NO(ASSERTION|NE)$/.test(l));
    out.push(
      normalizeComponent({
        name: p.name,
        version: p.versionInfo,
        purl: purlRef?.referenceLocator,
        type: (p.primaryPackagePurpose || 'library').toLowerCase(),
        licenses: license ? [license] : [],
        supplier: p.supplier && p.supplier !== 'NOASSERTION' ? p.supplier.replace(/^(Organization|Person):\s*/, '') : null,
      }),
    );
  }
  return {
    format: 'SPDX',
    specVersion: doc.spdxVersion.replace(/^SPDX-/, ''),
    subject: subject || (doc.name ? { name: doc.name, version: null } : null),
    components: dedupe(out),
  };
}
