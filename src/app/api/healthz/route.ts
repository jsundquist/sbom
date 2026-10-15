import { sql } from 'drizzle-orm';
import { NextResponse } from 'next/server';
import { getDb } from '@/db';

export async function GET() {
  try {
    await getDb().execute(sql`select 1`);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ ok: false, error: (err as Error).message }, { status: 503 });
  }
}
