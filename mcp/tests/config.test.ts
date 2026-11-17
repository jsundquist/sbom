import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  it('reads the URL and token, trims trailing slashes and defaults the timeout', () => {
    const c = loadConfig({ DASHBOARD_URL: 'https://sbom.example.com/', DASHBOARD_READ_TOKEN: 's3cret' });
    expect(c).toEqual({ baseUrl: 'https://sbom.example.com', token: 's3cret', timeoutMs: 10_000 });
  });

  it('accepts a timeout override', () => {
    const c = loadConfig({ DASHBOARD_URL: 'http://localhost:3000', DASHBOARD_READ_TOKEN: 't', DASHBOARD_TIMEOUT_MS: '2500' });
    expect(c.timeoutMs).toBe(2500);
  });

  it('names the missing variables without echoing any value', () => {
    expect(() => loadConfig({ DASHBOARD_URL: 'not a url', DASHBOARD_READ_TOKEN: 'hunter2' })).toThrow(/DASHBOARD_URL/);
    try {
      loadConfig({ DASHBOARD_URL: 'not a url', DASHBOARD_READ_TOKEN: 'hunter2' });
    } catch (e) {
      expect(String(e)).not.toContain('hunter2');
    }
    expect(() => loadConfig({ DASHBOARD_URL: 'http://x.test' })).toThrow(/DASHBOARD_READ_TOKEN/);
  });

  it('rejects non-http URLs', () => {
    expect(() => loadConfig({ DASHBOARD_URL: 'file:///etc/passwd', DASHBOARD_READ_TOKEN: 't' })).toThrow(/DASHBOARD_URL/);
  });
});
