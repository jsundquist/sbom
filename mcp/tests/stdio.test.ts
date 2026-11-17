import { PassThrough } from 'node:stream';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ReadBuffer, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { afterEach, describe, expect, it } from 'vitest';
import { DashboardClient, type FetchFn } from '../src/client.js';
import { createServer } from '../src/server.js';

// Newline-delimited JSON-RPC over a pair of streams: the same framing the real stdio transport uses.
function clientTransport(toServer: PassThrough, fromServer: PassThrough): Transport {
  const buffer = new ReadBuffer();
  const t: Transport = {
    async start() {
      fromServer.on('data', (chunk: Buffer) => {
        buffer.append(chunk);
        for (let m = buffer.readMessage(); m; m = buffer.readMessage()) {
          t.onmessage?.(m);
        }
      });
    },
    async send(message: JSONRPCMessage) {
      toServer.write(serializeMessage(message));
    },
    async close() {
      t.onclose?.();
    },
  };
  return t;
}

const config = { baseUrl: 'https://sbom.test', token: 'tok', timeoutMs: 1000 };
const closers: (() => Promise<void>)[] = [];

async function connect(fetchFn: FetchFn) {
  const toServer = new PassThrough();
  const fromServer = new PassThrough();
  const server = createServer(new DashboardClient(config, fetchFn));
  await server.connect(new StdioServerTransport(toServer, fromServer));
  const client = new Client({ name: 'smoke', version: '0.0.0' });
  await client.connect(clientTransport(toServer, fromServer));
  closers.push(
    () => client.close(),
    () => server.close(),
  );
  return client;
}

afterEach(async () => {
  await Promise.all(closers.splice(0).map((c) => c()));
});

describe('stdio smoke', () => {
  it('completes the handshake and lists only the ping tool', async () => {
    const client = await connect(async () => new Response('{}'));
    expect(client.getServerVersion()?.name).toBe('sbom-dashboard');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['ping']);
  });

  it('ping calls /api/v1/summary with the bearer token through the fake fetch', async () => {
    const calls: { url: string; auth: string | null }[] = [];
    const client = await connect(async (url, init) => {
      calls.push({ url: String(url), auth: new Headers(init?.headers).get('authorization') });
      return new Response(JSON.stringify({ stats: { components: 12, vulnerabilities: 3 }, projects: [] }));
    });
    const res = await client.callTool({ name: 'ping', arguments: {} });
    expect(res.isError).toBeFalsy();
    expect(res.content).toEqual([{ type: 'text', text: 'Dashboard reachable: 12 components, 3 vulnerabilities.' }]);
    expect(calls).toEqual([{ url: 'https://sbom.test/api/v1/summary', auth: 'Bearer tok' }]);
  });

  it('ping returns a tool error, not a crash, when the dashboard refuses the token', async () => {
    const client = await connect(async () => new Response('{}', { status: 401 }));
    const res = await client.callTool({ name: 'ping', arguments: {} });
    expect(res.isError).toBe(true);
    expect(res.content).toEqual([{ type: 'text', text: 'Dashboard answered HTTP 401' }]);
  });
});
