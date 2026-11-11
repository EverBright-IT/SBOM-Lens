import { createServer } from 'node:http';
import type { IncomingHttpHeaders, RequestListener, Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { webHost } from './webHost';

/**
 * The browser host against real HTTP servers. A stored token rides along as a
 * request header, and fetch repeats custom headers such as PRIVATE-TOKEN
 * against whatever address a redirect names. So the answer of one host must
 * never turn into a request to another.
 */

const servers: Server[] = [];

function listen(handler: RequestListener): Promise<string> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    servers.push(server);
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
    });
  });
}

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    server.close();
  }
});

describe('webHost.fetchDocument', () => {
  it.each([301, 302, 303, 307, 308])(
    'does not follow a %i, so the token never reaches the host it names',
    async (status) => {
      const foreign: IncomingHttpHeaders[] = [];
      const foreignHost = await listen((req, res) => {
        foreign.push(req.headers);
        res.end('collected');
      });
      const tokenHost = await listen((_req, res) => {
        res.writeHead(status, { location: `${foreignHost}/collect` }).end();
      });

      const result = await webHost.fetchDocument(`${tokenHost}/weiter`, {
        'PRIVATE-TOKEN': 'secret',
      });

      expect(foreign).toEqual([]);
      expect(result).toEqual({ ok: false });
    },
  );

  it('does not follow a redirect without a token either', async () => {
    const foreign: IncomingHttpHeaders[] = [];
    const foreignHost = await listen((req, res) => {
      foreign.push(req.headers);
      res.end('collected');
    });
    const namedHost = await listen((_req, res) => {
      res.writeHead(302, { location: `${foreignHost}/collect` }).end();
    });

    const result = await webHost.fetchDocument(`${namedHost}/weiter`);

    expect(foreign).toEqual([]);
    expect(result).toEqual({ ok: false });
  });

  it('still sends the token to the address the caller named', async () => {
    const seen: IncomingHttpHeaders[] = [];
    const tokenHost = await listen((req, res) => {
      seen.push(req.headers);
      res.end('SPDX');
    });

    const result = await webHost.fetchDocument(`${tokenHost}/a.spdx`, {
      'PRIVATE-TOKEN': 'secret',
    });

    expect(seen.map((headers) => headers['private-token'])).toEqual(['secret']);
    expect(result.ok && new TextDecoder().decode(result.bytes)).toBe('SPDX');
  });
});
