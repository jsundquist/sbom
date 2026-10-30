import { sql } from 'drizzle-orm';
import { NextResponse } from 'next/server';
import { getDb } from '@/db';

export async function GET() {
  try {
    await getDb().execute(sql`select 1`);
    return NextResponse.json({ ok: true });
  } catch (err) {
    // Open endpoint: the driver message can carry the DB host and port, so it goes to the server log only.
    console.error('healthz: database check failed', err);
    return NextResponse.json({ ok: false }, { status: 503 });
  }
}
