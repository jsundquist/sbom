import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Agents kept appending entries at the bottom despite "Newest first", so enforce it.
function datedHeadings(file: string): string[] {
  const text = readFileSync(join(process.cwd(), file), 'utf8');
  return [...text.matchAll(/^## (\d{4}-\d{2}-\d{2})\b/gm)].map((m) => m[1]);
}

describe.each(['docs/progress.md', 'docs/progress-archive.md'])('%s', (file) => {
  it('lists dated entries newest first', () => {
    const dates = datedHeadings(file);
    expect(dates.length).toBeGreaterThan(0);
    expect(dates).toEqual([...dates].sort().reverse());
  });
});

it('keeps every archived entry older than every current one', () => {
  const current = datedHeadings('docs/progress.md');
  const archived = datedHeadings('docs/progress-archive.md');
  expect(archived[0] <= current[current.length - 1]).toBe(true);
});
