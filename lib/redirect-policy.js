/**
 * Redirect policy for subscription fetches.
 *
 * A subscription URL is followed by hand rather than by the HTTP client, because
 * every hop has to be re-validated against the SSRF guard. That makes the loop
 * policy security-relevant, and this module is where the rules live so they can
 * be tested without a network:
 *
 * - **Hop limit.** A redirect chain is bounded; without a bound a hostile server
 *   can hold the fetch open forever one hop at a time.
 * - **Scheme rules.** `http:` and `https:` only. Following a redirect to
 *   `file:`, `data:` or `ftp:` would turn a subscription link into an arbitrary
 *   local-file or protocol read — the guard only reasons about http targets.
 * - **Cycle detection.** A chain that returns to an already-visited URL is a loop;
 *   stopping on it is cheaper and clearer than exhausting the hop budget.
 * - **Downgrade.** https → http silently strips the transport protection the user
 *   relied on, so it is refused rather than followed.
 */

/** Maximum redirect hops before the chain is refused. */
export const MAX_REDIRECT_HOPS = 5;

/** Protocols a subscription redirect may target. */
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/**
 * Decide what to do with one redirect.
 *
 * @param {URL} current   The URL that just answered with a redirect.
 * @param {string | undefined} location  The raw `Location` header.
 * @param {Set<string>} visited  Normalized URLs already fetched (mutated).
 * @param {number} hop    How many redirects have been followed so far.
 * @returns {{ action: 'follow', url: URL } | { action: 'stop', reason: string }}
 *   `stop` means "return this response to the caller as-is"; the reason is for
 *   diagnostics and never reaches the user verbatim.
 */
export function resolveRedirect(current, location, visited, hop) {
  if (typeof location !== 'string' || location.trim() === '') {
    return { action: 'stop', reason: 'missing-location' };
  }
  if (hop >= MAX_REDIRECT_HOPS) {
    return { action: 'stop', reason: 'too-many-hops' };
  }
  let next;
  try {
    next = new URL(location, current);
  } catch {
    return { action: 'stop', reason: 'invalid-location' };
  }
  if (!ALLOWED_PROTOCOLS.has(next.protocol)) {
    return { action: 'stop', reason: `protocol-not-allowed:${next.protocol}` };
  }
  // Downgrading to plaintext would discard the protection the user had.
  if (current.protocol === 'https:' && next.protocol === 'http:') {
    return { action: 'stop', reason: 'downgrade-refused' };
  }
  // The fragment never reaches the server, so it must not split one URL into two
  // "different" cycle-detection keys.
  const key = normalizeForVisit(next);
  if (visited.has(key)) return { action: 'stop', reason: 'redirect-loop' };
  visited.add(key);
  return { action: 'follow', url: next };
}

/**
 * A comparison key for cycle detection.
 *
 * Lowercases the host, drops the default port, and clears the fragment — three
 * differences that do not change what the server is asked for, but would let a
 * loop hide behind cosmetic variation.
 *
 * @param {URL} url
 * @returns {string}
 */
export function normalizeForVisit(url) {
  const copy = new URL(url.href);
  copy.hash = '';
  copy.hostname = copy.hostname.toLowerCase();
  const isDefaultPort =
    (copy.protocol === 'http:' && copy.port === '80') ||
    (copy.protocol === 'https:' && copy.port === '443');
  if (isDefaultPort) copy.port = '';
  return copy.href;
}