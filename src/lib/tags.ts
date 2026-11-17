import { z } from 'zod';

/** Free-form labels the uploader attaches to a Project (CONTEXT.md, ADR 0004). */
export const MAX_TAGS = 20;
export const MAX_TAG_LENGTH = 40;

const tag = z
  .string()
  .min(1)
  .max(MAX_TAG_LENGTH)
  .regex(/^[a-z0-9:_-]+$/);

export type ParsedTags = { ok: true; tags: string[] } | { ok: false; error: string };

/** Parses the comma-separated `tags` upload field: trimmed, lower-cased, de-duplicated, validated. Nothing sent means none. */
export function parseTags(input: string | undefined): ParsedTags {
  const tags = [
    ...new Set(
      (input ?? '')
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
  for (const t of tags) {
    if (!tag.safeParse(t).success) {
      return {
        ok: false,
        error: `Invalid tag "${t.slice(0, 50)}": use 1-${MAX_TAG_LENGTH} characters from a-z, 0-9, colon, underscore and hyphen`,
      };
    }
  }
  if (tags.length > MAX_TAGS) {
    return { ok: false, error: `Too many tags: at most ${MAX_TAGS}, got ${tags.length}` };
  }
  return { ok: true, tags };
}
