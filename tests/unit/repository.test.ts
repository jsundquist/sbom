import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { legacyRepositoryForms, normalizeRepository } from '@/lib/repository';
import { resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { GET as listProjectsRoute } from '@/app/api/v1/projects/route';
import { projects } from '@/db/schema';
import { listProjects } from '@/server/inventory';
import { createTestDb, fixture } from './helpers';

describe('normalizeRepository', () => {
  test.each([
    ['https://github.com/acme/web', 'github.com/acme/web'],
    ['http://github.com/acme/web', 'github.com/acme/web'],
    ['https://github.com/acme/web.git', 'github.com/acme/web'],
    ['https://github.com/acme/web/', 'github.com/acme/web'],
    ['https://github.com/acme/web.git/', 'github.com/acme/web'],
    ['https://github.com/acme/web/tree/main', 'github.com/acme/web'],
    ['https://user:token@github.com/acme/web.git', 'github.com/acme/web'],
    ['git@github.com:acme/web.git', 'github.com/acme/web'],
    ['git@github.com:acme/web', 'github.com/acme/web'],
    ['ssh://git@github.com/acme/web.git', 'github.com/acme/web'],
    ['ssh://git@github.com:22/acme/web.git', 'github.com/acme/web'],
    ['git://github.com/acme/web.git', 'github.com/acme/web'],
    ['git+https://github.com/acme/web.git', 'github.com/acme/web'],
    ['HTTPS://GitHub.com/Acme/Web', 'github.com/acme/web'],
    ['  github.com/Acme/Web  ', 'github.com/acme/web'],
    ['www.github.com/acme/web', 'github.com/acme/web'],
    // The Action sends GITHUB_REPOSITORY, which has no host.
    ['acme/web', 'github.com/acme/web'],
    ['Acme/Web.git', 'github.com/acme/web'],
    ['acme/web.js', 'github.com/acme/web.js'],
    // Non-GitHub hosts stay host/path; host is lowercased, path keeps its case.
    ['https://GitLab.com/Group/Sub/Repo.git', 'gitlab.com/Group/Sub/Repo'],
    ['git@gitlab.example.com:Group/Repo.git', 'gitlab.example.com/Group/Repo'],
    ['ssh://git@bitbucket.org:7999/team/repo.git', 'bitbucket.org/team/repo'],
    ['gitlab.com/group/repo', 'gitlab.com/group/repo'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeRepository(input)).toBe(expected);
  });

  test.each(['', '   ', 'web', 'https://github.com', 'https://github.com/acme', '/', '//'])('%j is not a repository', (input) => {
    expect(normalizeRepository(input)).toBeNull();
  });

  test('is idempotent', () => {
    for (const input of ['git@github.com:Acme/Web.git', 'acme/web', 'https://gitlab.com/G/R.git']) {
      const once = normalizeRepository(input)!;
      expect(normalizeRepository(once)).toBe(once);
    }
  });
});

describe('legacyRepositoryForms', () => {
  test('lists the raw shapes an old row could hold, github adds the bare owner/repo', () => {
    const forms = legacyRepositoryForms('github.com/acme/web');
    expect(forms).toEqual(
      expect.arrayContaining([
        'github.com/acme/web',
        'acme/web',
        'https://github.com/acme/web',
        'https://github.com/acme/web.git',
        'git@github.com:acme/web.git',
      ]),
    );
  });

  test('other hosts get no bare form', () => {
    expect(legacyRepositoryForms('gitlab.com/g/r')).not.toContain('g/r');
  });
});

const TOKEN = 'test-token';
const BASE = 'http://dash.test';
let db: Db;
let close: () => Promise<void>;

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  process.env.UPLOAD_TOKENS = TOKEN;
  vi.stubEnv('OWNER_GITHUB_ID', '');
  vi.stubEnv('ALLOW_OPEN_READS', 'true');
  resetEnv();
  resetRateLimits();
});
afterEach(async () => {
  vi.unstubAllEnvs();
  delete process.env.UPLOAD_TOKENS;
  resetEnv();
  await close();
});

const post = (query: string) =>
  upload(
    new Request(`${BASE}/api/v1/sboms${query}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify(fixture('cyclonedx.json')),
    }),
  );
const repoOf = async (name: string) => (await listProjects(db)).find((p) => p.name === name)?.repository;
const lookup = async (repository: string) =>
  (await (await listProjectsRoute(new Request(`${BASE}/api/v1/projects?repository=${encodeURIComponent(repository)}`))).json()) as {
    name: string;
  }[];

describe('ingest stores the normalised repository', () => {
  test.each(['git@github.com:Acme/Web.git', 'acme/web', 'https://github.com/acme/web/'])('upload with %s', async (repository) => {
    expect((await post(`?project=p&repository=${encodeURIComponent(repository)}`)).status).toBe(201);
    expect(await repoOf('p')).toBe('github.com/acme/web');
  });

  test('an upload without a repository keeps the stored one', async () => {
    await post('?project=p&repository=acme/web');
    await post('?project=p');
    expect(await repoOf('p')).toBe('github.com/acme/web');
  });

  test('an unparseable repository is ignored and keeps the stored one', async () => {
    await post('?project=p&repository=acme/web');
    await post('?project=p&repository=nonsense');
    expect(await repoOf('p')).toBe('github.com/acme/web');
  });
});

describe('GET /api/v1/projects?repository=', () => {
  test('matches any spelling of the same repository, not other repositories', async () => {
    await post('?project=a&repository=acme/web');
    await post('?project=b&repository=acme/web');
    await post('?project=c&repository=acme/other');
    for (const q of ['https://github.com/Acme/Web.git', 'git@github.com:acme/web.git', 'acme/web', 'github.com/acme/web']) {
      expect((await lookup(q)).map((p) => p.name)).toEqual(['a', 'b']);
    }
  });

  test('also finds a Project still holding the old unnormalised form until it is re-uploaded', async () => {
    await post('?project=old');
    await db.update(projects).set({ repository: 'Acme/Web' });
    expect((await lookup('github.com/acme/web')).map((p) => p.name)).toEqual(['old']);
    await db.update(projects).set({ repository: 'https://github.com/acme/web.git' });
    expect((await lookup('acme/web')).map((p) => p.name)).toEqual(['old']);
    await post('?project=old&repository=acme/web');
    expect(await repoOf('old')).toBe('github.com/acme/web');
  });

  test('an unparseable filter is a 400, an empty one returns everything', async () => {
    await post('?project=a&repository=acme/web');
    expect((await listProjectsRoute(new Request(`${BASE}/api/v1/projects?repository=nonsense`))).status).toBe(400);
    expect(await lookup('')).toHaveLength(1);
  });
});
