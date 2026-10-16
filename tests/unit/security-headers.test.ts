import { describe, expect, test } from 'vitest';
import { securityHeaders } from '@/lib/security-headers';

const get = (isDev: boolean, key: string) => securityHeaders(isDev).find((h) => h.key === key)?.value;

describe('security headers', () => {
  test('sets the baseline headers', () => {
    expect(get(false, 'X-Frame-Options')).toBe('DENY');
    expect(get(false, 'X-Content-Type-Options')).toBe('nosniff');
    expect(get(false, 'Referrer-Policy')).toBe('strict-origin-when-cross-origin');
  });

  test('production CSP forbids framing, plugins and eval', () => {
    const csp = get(false, 'Content-Security-Policy')!;
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain('unsafe-eval');
  });

  test('dev CSP allows eval and websockets for HMR', () => {
    const csp = get(true, 'Content-Security-Policy')!;
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).toContain('ws:');
  });
});
