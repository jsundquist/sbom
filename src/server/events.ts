import { desc, sql } from 'drizzle-orm';
import type { Db } from '@/db';
import { events, type EventKind } from '@/db/schema';

export interface AuditEvent {
  id: number;
  at: string;
  kind: EventKind;
  projectId: number | null;
  projectName: string;
  tokenFingerprint: string | null;
  detail: Record<string, unknown>;
}

/** The audit trail, newest first, with the total for pagination. */
export async function listEvents(db: Db, { limit, offset = 0 }: { limit?: number; offset?: number } = {}) {
  const query = db.select().from(events).orderBy(desc(events.at), desc(events.id)).offset(offset);
  const rows = await (limit === undefined ? query : query.limit(limit));
  const [{ total }] = await db.select({ total: sql<number>`count(*)::int` }).from(events);
  const items: AuditEvent[] = rows.map((r) => ({ ...r, at: r.at.toISOString() }));
  return { items, total };
}
