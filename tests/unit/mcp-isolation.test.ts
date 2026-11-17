import path from 'node:path';
import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

const root = path.resolve(import.meta.dirname, '..', '..');

// Lints a snippet as if it lived in mcp/, to prove the ADR 0003 boundary is enforced and not just documented.
async function lintAsMcp(code: string) {
  const eslint = new ESLint({ cwd: root });
  const [result] = await eslint.lintText(code, { filePath: path.join(root, 'mcp', 'src', 'config.ts') });
  return result.messages.filter((m) => m.ruleId === '@typescript-eslint/no-restricted-imports');
}

describe('mcp/ isolation from src/', () => {
  it.each([
    ["import { env } from '@/lib/env';"],
    ["import { env } from '../../src/lib/env';"],
    ["import { env } from '../../src/server/inventory';"],
  ])('rejects %s', async (code) => {
    expect(await lintAsMcp(`${code}\nexport const x = env;\n`)).toHaveLength(1);
  });

  it('allows imports within mcp/', async () => {
    expect(await lintAsMcp("import { z } from 'zod';\nimport { x } from './client.js';\nexport const y = [z, x];\n")).toHaveLength(0);
  });
});
