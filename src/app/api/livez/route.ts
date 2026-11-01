import { NextResponse } from 'next/server';

// Liveness only: no database access, so a Postgres outage never gets the web pod restarted. Readiness is /api/healthz.
export function GET() {
  return NextResponse.json({ ok: true });
}
