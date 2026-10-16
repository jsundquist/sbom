import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';
import prettier from 'eslint-config-prettier/flat';

// Import-direction rules from AGENTS.md "Layering rules". Type-only imports are allowed where noted.
const layer = (files, from, message, allowTypeImports = false) => ({
  files,
  rules: {
    '@typescript-eslint/no-restricted-imports': [
      'error',
      { patterns: [{ group: from.flatMap((d) => [`@/${d}`, `@/${d}/**`]), message, allowTypeImports }] },
    ],
  },
});

const layering = [
  layer(['src/lib/**', 'src/sbom/**'], ['server', 'worker', 'app', 'components'], 'lib/ and sbom/ must not import upper layers.'),
  layer(['src/db/**'], ['server', 'worker', 'app', 'components'], 'db/ must not import app-level code.'),
  layer(['src/server/**'], ['worker', 'app', 'components'], 'server/ must not import worker/, app/ or components/.'),
  layer(['src/worker/**'], ['server', 'app', 'components'], 'worker/ talks to the app only through Postgres.'),
  layer(['src/components/**'], ['db', 'server', 'worker'], 'components/ may only import types from db/ and server/.', true),
];

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  prettier,
  globalIgnores(['.next/**', 'out/**', 'node_modules/**', 'drizzle/**', 'playwright-report/**', 'test-results/**', 'next-env.d.ts']),
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // Always use braces (so `return` is never inline after an `if`).
      curly: ['error', 'all'],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
    },
  },
  ...layering,
]);
