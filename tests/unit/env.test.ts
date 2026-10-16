import { describe, expect, it } from 'vitest';
import { MIN_WORKER_POLL_SECONDS, parseEnv } from '@/lib/env';

const base = { DATABASE_URL: 'postgres://u:p@localhost:5432/db' };

describe('WORKER_POLL_SECONDS', () => {
  it('defaults to a few runs per day', () => {
    expect(parseEnv(base).WORKER_POLL_SECONDS).toBe(6 * 3600);
  });

  it('raises values below the floor so upstream APIs are not hammered', () => {
    expect(parseEnv({ ...base, WORKER_POLL_SECONDS: '5' }).WORKER_POLL_SECONDS).toBe(MIN_WORKER_POLL_SECONDS);
  });

  it('keeps values at or above the floor', () => {
    expect(parseEnv({ ...base, WORKER_POLL_SECONDS: '7200' }).WORKER_POLL_SECONDS).toBe(7200);
  });
});
