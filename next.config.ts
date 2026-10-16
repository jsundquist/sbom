import type { NextConfig } from 'next';
import { securityHeaders } from './src/lib/security-headers';

const nextConfig: NextConfig = {
  serverExternalPackages: ['pg'],
  poweredByHeader: false,
  // `next dev` otherwise rewrites a managed block into AGENTS.md; project instructions are maintained by hand.
  agentRules: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders(process.env.NODE_ENV !== 'production') }];
  },
};

export default nextConfig;
