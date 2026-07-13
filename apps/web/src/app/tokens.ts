import { pref } from './brand';
import { host } from '../host/adapter';

/**
 * Per-host access tokens for fetching SBOMs from private registries
 * (e.g. GitLab generic packages). Stored via the host's secret store —
 * sessionStorage in the browser (dies with the tab), the editor's secret
 * storage in extension hosts.
 */

export type TokenScheme = 'private-token' | 'bearer';

export interface HostToken {
  scheme: TokenScheme;
  value: string;
}

const keyFor = (hostName: string) => pref(`token.${hostName}`);

export async function tokenForUrl(url: string): Promise<HostToken | undefined> {
  try {
    const raw = await host().secretGet(keyFor(new URL(url).host));
    return raw ? (JSON.parse(raw) as HostToken) : undefined;
  } catch {
    return undefined;
  }
}

export async function rememberToken(url: string, token: HostToken | null): Promise<void> {
  try {
    await host().secretSet(keyFor(new URL(url).host), token ? JSON.stringify(token) : null);
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
