/** What a Project is (CONTEXT.md, ADR 0004). Shared by the schema, upload validation and the UI. */
export const PROJECT_KINDS = ['application', 'library', 'image', 'host'] as const;

export type ProjectKind = (typeof PROJECT_KINDS)[number];

export const DEFAULT_PROJECT_KIND: ProjectKind = 'application';
