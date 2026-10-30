import NextAuth from 'next-auth';
import { checkRateLimit } from '@/server/api';
import { authOptions } from '@/server/auth';

type Ctx = { params: Promise<{ nextauth: string[] }> };

// Options are built per request so env() is read at runtime, not at build time.
async function handler(req: Request, ctx: Ctx) {
  const limited = checkRateLimit(req, Date.now(), 'auth');
  if (limited) {
    return limited;
  }
  return NextAuth(req as never, ctx as never, authOptions());
}

export { handler as GET, handler as POST };
