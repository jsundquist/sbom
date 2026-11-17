#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { DashboardClient } from './client.js';
import { loadConfig } from './config.js';
import { createServer } from './server.js';

async function main() {
  const client = new DashboardClient(loadConfig());
  await createServer(client).connect(new StdioServerTransport());
}

main().catch((e: unknown) => {
  // stdout carries the protocol, so diagnostics go to stderr.
  console.error(e instanceof Error ? e.message : 'Failed to start');
  process.exit(1);
});
