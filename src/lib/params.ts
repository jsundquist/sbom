/** Parses a positive integer route parameter. */
export function parseIdOrNull(value: string): number | null {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}
