import { pref } from './brand';
import { host } from '../host/adapter';

/**
 * Access tokens for fetching SBOMs from private registries (e.g. GitLab
 * generic packages), one per origin: scheme, host and port. A token saved for
 * https://host must never ride along on a plain http:// request that a
 * document points at, so the scheme is part of the key, and only http and
 * https carry tokens at all. Stored via the host's secret store:
 * sessionStorage in the browser (dies with the tab), the editor's secret
 * storage in extension hosts.
 */

export type TokenScheme = 'private-token' | 'bearer';

export interface HostToken {
  scheme: TokenScheme;
  value: string;
}

const keyFor = (origin: string) => pref(`token.${origin}`);
/** Earlier versions keyed by the bare host. Such a token still serves https, never http. */
const legacyKeyFor = (hostName: string) => pref(`token.${hostName}`);

function tokenTarget(url: string): URL | undefined {
  const target = new URL(url);
  return target.protocol === 'https:' || target.protocol === 'http:' ? target : undefined;
}

export async function tokenForUrl(url: string): Promise<HostToken | undefined> {
  try {
    const target = tokenTarget(url);
    if (!target) return undefined;
    const raw =
      (await host().secretGet(keyFor(target.origin))) ??
      (target.protocol === 'https:' ? await host().secretGet(legacyKeyFor(target.host)) : null);
    return raw ? (JSON.parse(raw) as HostToken) : undefined;
  } catch {
    return undefined;
  }
}

export async function rememberToken(url: string, token: HostToken | null): Promise<void> {
  try {
    const target = tokenTarget(url);
    if (!target) return;
    await host().secretSet(keyFor(target.origin), token ? JSON.stringify(token) : null);
    // A legacy entry would keep answering for https: saving replaces it, forgetting clears it.
    if (target.protocol === 'https:') await host().secretSet(legacyKeyFor(target.host), null);
  } catch {
    // Tokens are a convenience, not a requirement.
  }
}

export function authHeaders(token: HostToken | undefined): Record<string, string> {
  if (!token) return {};
  return token.scheme === 'private-token'
    ? { 'PRIVATE-TOKEN': token.value }
    : { Authorization: `Bearer ${token.value}` };
}
