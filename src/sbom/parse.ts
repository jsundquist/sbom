// Normalizes CycloneDX (JSON) and SPDX (JSON) documents into a flat component list.
import { z } from 'zod';
import { displayName, packageKey, parsePurl } from '@/lib/purl';

export class SbomParseError extends Error {}

export interface ParsedComponent {
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  packageKey: string | null;
  type: string;
  licenses: string | null;
  supplier: string | null;
}

/** Identifies a component within one SBOM: package and version, or the name when there is no purl. */
export const componentKey = (c: Pick<ParsedComponent, 'packageKey' | 'name' | 'version'>) => `${c.packageKey ?? c.name}@${c.version}`;

export interface ParsedSbom {
  format: 'CycloneDX' | 'SPDX';
  specVersion: string | null;
  subject: { name: string; version: string | null } | null;
  components: ParsedComponent[];
  /** `from` depends on `to`; both are `componentKey`s of entries in `components`. */
  edges: { from: string; to: string }[];
  /** Components the SBOM subject depends on directly, or null when the SBOM does not say. */
  direct: string[] | null;
}

const str = z.string().nullish().catch(null);

type CdxComponent = {
  'bom-ref'?: string | null;
  type?: string | null;
  name?: string | null;
  group?: string | null;
  version?: string | null;
  purl?: string | null;
  publisher?: string | null;
  supplier?: { name?: string | null } | null;
  licenses?: { expression?: string | null; license?: { id?: string | null; name?: string | null } | null }[] | null;
  components?: CdxComponent[] | null;
};

const cdxComponent: z.ZodType<CdxComponent> = z.lazy(() =>
  z.looseObject({
    'bom-ref': str,
    type: str,
    name: str,
    group: str,
    version: str,
    purl: str,
    publisher: str,
    supplier: z.looseObject({ name: str }).nullish().catch(null),
    licenses: z
      .array(z.looseObject({ expression: str, license: z.looseObject({ id: str, name: str }).nullish() }))
      .nullish()
      .catch(null),
    components: z.array(cdxComponent).nullish(),
  }),
);

const cycloneDx = z.looseObject({
  bomFormat: z.literal('CycloneDX'),
  specVersion: str,
  metadata: z.looseObject({ component: cdxComponent.nullish() }).nullish(),
  components: z.array(cdxComponent).nullish(),
  dependencies: z
    .array(z.looseObject({ ref: str, dependsOn: z.array(z.string()).nullish().catch(null) }))
    .nullish()
    .catch(null),
});

const spdx = z.looseObject({
  spdxVersion: z.string(),
  SPDXID: str,
  name: str,
  documentDescribes: z.array(z.string()).nullish(),
  relationships: z
    .array(z.looseObject({ spdxElementId: str, relationshipType: str, relatedSpdxElement: str }))
    .nullish()
    .catch(null),
  packages: z
    .array(
      z.looseObject({
        SPDXID: str,
        name: z.string(),
        versionInfo: str,
        licenseConcluded: str,
        licenseDeclared: str,
        supplier: str,
        primaryPackagePurpose: str,
        externalRefs: z
          .array(z.looseObject({ referenceType: str, referenceLocator: str }))
          .nullish()
          .catch(null),
      }),
    )
    .nullish(),
});

export function parseSbom(input: unknown): ParsedSbom {
  let doc = input;
  // GitHub's dependency graph export wraps the SPDX document in { "sbom": ... }.
  if (doc && typeof doc === 'object' && 'sbom' in doc && doc.sbom && typeof doc.sbom === 'object') {
    doc = doc.sbom;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new SbomParseError('SBOM must be a JSON object');
  }
  if ('bomFormat' in doc) {
    return parseCycloneDx(validate(cycloneDx, doc, 'CycloneDX'));
  }
  if ('spdxVersion' in doc) {
    return parseSpdx(validate(spdx, doc, 'SPDX'));
  }
  throw new SbomParseError('Unsupported SBOM format: expected CycloneDX JSON or SPDX JSON');
}

function validate<T>(schema: z.ZodType<T>, doc: unknown, label: string): T {
  const result = schema.safeParse(doc);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new SbomParseError(`Invalid ${label} document at ${issue.path.join('.') || '(root)'}: ${issue.message}`);
  }
  return result.data;
}

function normalize(c: {
  name: string;
  version?: string | null;
  purl?: string | null;
  type?: string | null;
  licenses: string[];
  supplier?: string | null;
}): ParsedComponent {
  const parsed = parsePurl(c.purl);
  return {
    name: parsed ? displayName(parsed) : c.name,
    version: c.version || parsed?.version || null,
    purl: c.purl || null,
    ecosystem: parsed?.type ?? null,
    packageKey: parsed ? packageKey(parsed) : null,
    type: c.type || 'library',
    licenses: c.licenses.length ? [...new Set(c.licenses)].join(' OR ') : null,
    supplier: c.supplier || null,
  };
}

function dedupe(components: ParsedComponent[]): ParsedComponent[] {
  const seen = new Map<string, ParsedComponent>();
  for (const c of components) {
    if (!c.name) {
      continue;
    }
    const key = componentKey(c);
    if (!seen.has(key)) {
      seen.set(key, c);
    }
  }
  return [...seen.values()];
}

function parseCycloneDx(doc: z.infer<typeof cycloneDx>): ParsedSbom {
  const root = doc.metadata?.component;
  const out: ParsedComponent[] = [];
  const keyById = new Map<string, string>();
  const walk = (list: CdxComponent[] | null | undefined) => {
    for (const c of list ?? []) {
      if (c.type !== 'file' && c.name && !(root?.purl && c.purl === root.purl)) {
        const component = normalize({
          name: c.group ? `${c.group}/${c.name}` : c.name,
          version: c.version,
          purl: c.purl,
          type: c.type,
          licenses: (c.licenses ?? []).map((l) => l.expression || l.license?.id || l.license?.name).filter((l): l is string => !!l),
          supplier: c.supplier?.name || c.publisher,
        });
        out.push(component);
        if (c['bom-ref']) {
          keyById.set(c['bom-ref'], componentKey(component));
        }
      }
      walk(c.components);
    }
  };
  walk(doc.components);
  const components = dedupe(out);
  const graph = buildGraph(
    components,
    (doc.dependencies ?? []).flatMap((d) => (d.ref ? (d.dependsOn ?? []).map((to) => ({ from: d.ref!, to })) : [])),
    keyById,
    new Set(root?.['bom-ref'] ? [root['bom-ref']] : []),
  );
  return {
    format: 'CycloneDX',
    specVersion: doc.specVersion ?? null,
    subject: root?.name ? { name: root.name, version: root.version ?? null } : null,
    components,
    ...graph,
  };
}

function parseSpdx(doc: z.infer<typeof spdx>): ParsedSbom {
  const described = new Set(doc.documentDescribes ?? []);
  for (const r of doc.relationships ?? []) {
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === doc.SPDXID && r.relatedSpdxElement) {
      described.add(r.relatedSpdxElement);
    }
  }
  const out: ParsedComponent[] = [];
  const keyById = new Map<string, string>();
  let subject: ParsedSbom['subject'] = null;
  for (const p of doc.packages ?? []) {
    if (p.SPDXID && described.has(p.SPDXID)) {
      subject ??= { name: p.name, version: p.versionInfo ?? null };
      continue;
    }
    const license = [p.licenseConcluded, p.licenseDeclared].find((l) => l && !/^NO(ASSERTION|NE)$/.test(l));
    const component = normalize({
      name: p.name,
      version: p.versionInfo,
      purl: p.externalRefs?.find((r) => r.referenceType === 'purl')?.referenceLocator,
      type: p.primaryPackagePurpose?.toLowerCase(),
      licenses: license ? [license] : [],
      supplier: p.supplier && p.supplier !== 'NOASSERTION' ? p.supplier.replace(/^(Organization|Person):\s*/, '') : null,
    });
    out.push(component);
    if (p.SPDXID) {
      keyById.set(p.SPDXID, componentKey(component));
    }
  }
  const components = dedupe(out);
  const graph = buildGraph(
    components,
    (doc.relationships ?? []).flatMap((r) => {
      if (!r.spdxElementId || !r.relatedSpdxElement) {
        return [];
      }
      // "A DEPENDENCY_OF B" reads in reverse: B depends on A.
      if (r.relationshipType === 'DEPENDS_ON') {
        return [{ from: r.spdxElementId, to: r.relatedSpdxElement }];
      }
      return r.relationshipType === 'DEPENDENCY_OF' ? [{ from: r.relatedSpdxElement, to: r.spdxElementId }] : [];
    }),
    keyById,
    described,
  );
  return {
    format: 'SPDX',
    specVersion: doc.spdxVersion.replace(/^SPDX-/, ''),
    subject: subject ?? (doc.name ? { name: doc.name, version: null } : null),
    components,
    ...graph,
  };
}

/**
 * Turns raw id-to-id relationships into component-key edges. Relationships to ids that are not kept components are
 * dropped; those from a root id become direct dependencies. `direct` stays null when no root relationship exists.
 */
function buildGraph(
  components: ParsedComponent[],
  relationships: { from: string; to: string }[],
  keyById: Map<string, string>,
  roots: Set<string>,
): Pick<ParsedSbom, 'edges' | 'direct'> {
  const kept = new Set(components.map(componentKey));
  const edges = new Map<string, { from: string; to: string }>();
  const direct = new Set<string>();
  let rootSeen = false;
  for (const r of relationships) {
    const to = keyById.get(r.to);
    if (!to || !kept.has(to)) {
      continue;
    }
    if (roots.has(r.from)) {
      rootSeen = true;
      direct.add(to);
      continue;
    }
    const from = keyById.get(r.from);
    if (from && kept.has(from) && from !== to) {
      edges.set(`${from} -> ${to}`, { from, to });
    }
  }
  return { edges: [...edges.values()], direct: rootSeen ? [...direct] : null };
}
