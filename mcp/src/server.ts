import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { DashboardClient, DashboardError } from './client.js';

const summarySchema = z.object({
  stats: z.object({ components: z.number(), vulnerabilities: z.number() }),
});

export function createServer(client: DashboardClient): McpServer {
  const server = new McpServer({ name: 'sbom-dashboard', version: '0.1.0' });

  // Connectivity check only; the real tools arrive with M-002.
  server.registerTool('ping', { description: 'Check that the SBOM dashboard is reachable with the configured read token.' }, async () => {
    try {
      const { stats } = await client.get('/api/v1/summary', summarySchema);
      return {
        content: [
          {
            type: 'text' as const,
            text: `Dashboard reachable: ${stats.components} components, ${stats.vulnerabilities} vulnerabilities.`,
          },
        ],
      };
    } catch (e) {
      const text = e instanceof DashboardError ? e.message : 'Unexpected error';
      return { isError: true, content: [{ type: 'text' as const, text }] };
    }
  });

  return server;
}
