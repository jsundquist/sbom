/** Parses a positive integer route parameter. */
export function parseIdOrNull(value: string): number | null {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Trend window in days: default 90, clamped to 1..365. */
export function parseDays(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 ? Math.min(n, 365) : 90;
}
