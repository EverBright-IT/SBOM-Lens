import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import { pref } from './brand';
import { rememberToken, tokenForUrl } from './tokens';

/**
 * Stored access tokens are keyed by origin. A token saved for an https
 * registry must never ride along on a plain http request to the same host,
 * which a loaded document can trigger through a reference URL.
 */

const secrets = new Map<string, string>();
const fakeHost = {
  kind: 'web',
  caps: { catalog: false },
  secretGet: async (key: string) => secrets.get(key) ?? null,
  secretSet: async (key: string, value: string | null) => {
    if (value === null) secrets.delete(key);
    else secrets.set(key, value);
  },
} as unknown as HostAdapter;

describe('stored tokens', () => {
  beforeEach(() => {
    setHost(fakeHost);
    secrets.clear();
  });

  it('never hands a token saved for https to plain http on the same host', async () => {
    await rememberToken('https://registry.example/a.spdx', { scheme: 'bearer', value: 'secret' });
    expect(await tokenForUrl('https://registry.example/b.spdx')).toEqual({ scheme: 'bearer', value: 'secret' });
    expect(await tokenForUrl('http://registry.example/b.spdx')).toBeUndefined();
  });

  it('serves a token saved for an http origin there, and only there', async () => {
    await rememberToken('http://intranet.example/a.spdx', { scheme: 'private-token', value: 'p' });
    expect(await tokenForUrl('http://intranet.example/b.spdx')).toEqual({ scheme: 'private-token', value: 'p' });
    expect(await tokenForUrl('https://intranet.example/b.spdx')).toBeUndefined();
  });

  it('still reads a token earlier versions saved under the bare host, for https only', async () => {
    secrets.set(pref('token.registry.example'), JSON.stringify({ scheme: 'bearer', value: 'old' }));
    expect(await tokenForUrl('https://registry.example/x')).toEqual({ scheme: 'bearer', value: 'old' });
    expect(await tokenForUrl('http://registry.example/x')).toBeUndefined();
  });

  it('forgetting a token also clears the entry earlier versions wrote', async () => {
    secrets.set(pref('token.registry.example'), JSON.stringify({ scheme: 'bearer', value: 'old' }));
    await rememberToken('https://registry.example/x', null);
    expect(await tokenForUrl('https://registry.example/x')).toBeUndefined();
  });

  it('keeps tokens away from schemes other than http and https', async () => {
    await rememberToken('https://registry.example/a.spdx', { scheme: 'bearer', value: 'secret' });
    expect(await tokenForUrl('ftp://registry.example/a.spdx')).toBeUndefined();
    expect(await tokenForUrl('file:///tmp/a.spdx')).toBeUndefined();
  });
});
