import { ingestUrl } from './ingest';
import { useAppStore } from './store';

/**
 * Deep links: `?url=<sbom-url>` opens a document straight from the address
 * bar, so a README, a release note, or a registry page can link to "this SBOM,
 * rendered" instead of "download this file, then find a viewer". Repeatable,
 * so a whole cascade can be linked at once:
 *
 *   https://sbom-lens.everbright-it.de/?url=<release>&url=<component>
 *
 * The query survives a reload, which is the point of a shareable link.
 *
 * A deep link is untrusted input: anyone can send one. Two rules follow, and
 * they are the reason this module exists instead of a one-liner in the app:
 *
 *   1. Only http(s). `javascript:`, `data:` and `file:` never reach a fetch.
 *   2. Stored access tokens are NOT attached (see `openDeepLinks`). A link
 *      someone sent you must not spend your credentials; if the source needs
 *      auth, the user opens the dialog and confirms that themselves.
 */

/**
 * How many documents one link may open. A cascade is a handful of files; a
 * link with hundreds would be a way to point someone else's browser at a
 * server, not a way to share an SBOM.
 */
export const MAX_DEEP_LINKS = 8;

export interface DeepLinks {
  urls: string[];
  /** Entries that were dropped, so the app can say so instead of silently ignoring them. */
  rejected: number;
}

/**
 * The http(s) URLs in a query string, in order, deduplicated and capped.
 * Pure, so the parsing rules are testable without a browser.
 */
export function readDeepLinks(search: string): DeepLinks {
  const urls: string[] = [];
  const seen = new Set<string>();
  let rejected = 0;

  for (const raw of new URLSearchParams(search).getAll('url')) {
    const value = raw.trim();
    if (value === '') continue;
    if (!isFetchableUrl(value)) {
      rejected++;
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    if (urls.length < MAX_DEEP_LINKS) urls.push(value);
    else rejected++;
  }

  return { urls, rejected };
}

/**
 * Absolute http(s) only. Relative URLs are rejected too: resolving them
 * against our own origin would let a link probe the deployment itself.
 */
function isFetchableUrl(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:';
}

/**
 * Opens every document a deep link names, in order, and reports what failed.
 * Sequential on purpose: the cascade resolves the same way it does when files
 * are dropped one after another, and one link never fans out into parallel
 * requests against someone's server.
 *
 * Stored tokens stay out of it. When a source answers 401/403, the From-URL
 * dialog opens prefilled instead, so attaching a credential remains a
 * deliberate act by the person holding it.
 */
export async function openDeepLinks(search: string): Promise<void> {
  const { urls, rejected } = readDeepLinks(search);
  const { actions } = useAppStore.getState();

  if (rejected > 0) {
    actions.toast(
      `${rejected} link${rejected === 1 ? '' : 's'} ignored: only http(s) URLs open this way, ${MAX_DEEP_LINKS} at most.`,
      'error',
    );
  }
  if (urls.length === 0) return;

  for (const url of urls) {
    const result = await ingestUrl(url, { useStoredToken: false });
    if (result.ok) continue;
    if (result.status === 401 || result.status === 403) {
      actions.toast(`${hostOf(url)} requires authentication for this document.`, 'error');
      actions.openUrlDialog(url);
      return; // one dialog at a time; the rest of the link is the user's call
    }
    actions.toast(`${hostOf(url)}: ${result.message ?? 'could not be opened.'}`, 'error');
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
