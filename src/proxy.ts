import { NextResponse, type NextRequest } from 'next/server';
import { denial, deny, ownerState } from '@/server/auth';

/** Paths that never need a session (the next-auth endpoints rate-limit themselves; see the route handler). */
function isOpenPath(path: string): boolean {
  return (
    path === '/api/healthz' ||
    path === '/api/auth' ||
    path.startsWith('/api/auth/') ||
    path.startsWith('/_next/static/') ||
    path === '/_next/image' ||
    path === '/icon.svg'
  );
}

/**
 * The two bearer-token routes keep their own UPLOAD_TOKENS check. Matched by method and exact path only, so a bearer
 * header on any other request gains nothing here.
 */
function isBearerRoute(method: string, path: string): boolean {
  return (method === 'POST' && path === '/api/v1/sboms') || (method === 'DELETE' && /^\/api\/v1\/projects\/[^/]+$/.test(path));
}

/** Machine-facing paths get JSON status codes; everything else is treated as a page navigation. */
function wantsJson(path: string): boolean {
  return path === '/api' || path.startsWith('/api/') || path.startsWith('/_next/') || path.split('/').pop()!.includes('.');
}

export async function proxy(req: NextRequest): Promise<NextResponse> {
  // Raw URL, not nextUrl: NextURL rewrites /_next/data/<build>/x.json to /x, which would hide the real path.
  const { pathname } = new URL(req.url);
  // Next serves /x and /x/ identically; normalise so a trailing slash cannot dodge or break the exact matches.
  const path = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  if (isOpenPath(path) || isBearerRoute(req.method, path)) {
    return NextResponse.next();
  }
  const d = denial(await ownerState(req.headers));
  if (!d) {
    return NextResponse.next();
  }
  if (wantsJson(path)) {
    return deny(d.status, d.message);
  }
  if (d.status === 503) {
    return new NextResponse(d.message, { status: 503 });
  }
  // There is no sign-in route: the AccessGate renders in place on "/". Leave "/" alone (no loop) and send every other
  // page URL there with the query dropped, so a probe learns nothing about which pages exist.
  if (path === '/') {
    return NextResponse.next();
  }
  const url = req.nextUrl.clone();
  url.pathname = '/';
  url.search = '';
  return NextResponse.redirect(url);
}
