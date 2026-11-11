/** Hops one request may take; servers redirect once or twice, to a store or a canonical address. */
export const MAX_REDIRECTS = 5;
const REDIRECT_STATUS = [301, 302, 303, 307, 308];

/**
 * GET that follows redirects by hand. fetch's own `follow` would request
 * whatever address an answer names and repeat the caller's headers there:
 * only Authorization is dropped on the way to another origin, a custom header
 * such as PRIVATE-TOKEN is not. Here a hop is only taken to an https address,
 * and what the caller sent stays with the origin the request started from.
 * Another origin gets the headers named in `portable` and nothing else.
 * `own` says whether the answer still is the starting origin's.
 */
export async function fetchFollowing(
  fetchFn: typeof fetch,
  url: string,
  headers: Record<string, string>,
  portable: readonly string[] = [],
): Promise<{ response: Response; own: boolean }> {
  const start = new URL(url);
  const elsewhere: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (portable.some((p) => p.toLowerCase() === name.toLowerCase())) elsewhere[name] = value;
  }
  let current = url;
  for (let hop = 0; ; hop++) {
    const own = new URL(current).origin === start.origin;
    const response = await fetchFn(current, { headers: own ? headers : elsewhere, redirect: 'manual' });
    const next = hop < MAX_REDIRECTS ? redirectTarget(response, current) : null;
    if (!next) return { response, own };
    await response.body?.cancel();
    current = next;
  }
}

/** The address a redirect answer names, if the request may go on to it. */
function redirectTarget(response: Response, from: string): string | null {
  const location = response.headers.get('location');
  if (!REDIRECT_STATUS.includes(response.status) || !location) return null;
  try {
    const target = new URL(location, from);
    return target.protocol === 'https:' ? target.href : null;
  } catch {
    return null;
  }
}
