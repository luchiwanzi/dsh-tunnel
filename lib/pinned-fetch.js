/**
 * A fetch that connects to an address the caller has ALREADY validated.
 *
 * The SSRF guard resolves a hostname and checks every answer; the ordinary
 * `fetch()` then resolves the same name *again*, on its own. Between the two
 * resolutions an attacker-controlled DNS record can change — the classic
 * rebinding window — so the address that was checked is not necessarily the
 * address that is contacted.
 *
 * This module closes that window: the validated addresses are passed in and are
 * the only ones ever dialled. The original hostname survives in the `Host`
 * header and in TLS (`servername`, so SNI and certificate validation still match
 * the name the user typed), which keeps ordinary subscription hosts working
 * unchanged.
 *
 * The dial is redirected with `createConnection` rather than by rewriting
 * `options.host`: Node rejects a request whose `Host` header disagrees with its
 * authority, and rewriting the authority would also break TLS identity and
 * virtual hosting. Overriding the socket keeps the request itself untouched.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';

/** Default socket factories; tests inject stand-ins to inspect the dial. */
export const defaultConnectors = { net: netConnect, tls: tlsConnect };

/**
 * A `createConnection` that dials `address` while presenting `url`'s identity.
 *
 * For `https:` the TLS name stays the user-visible hostname: `servername` drives
 * SNI and the certificate check, so a pinned connection validates the same
 * certificate the user's browser would. Only the socket's destination changes.
 *
 * @param {URL} url
 * @param {string} address Already validated by the SSRF guard.
 * @param {number} family 4 or 6.
 * @param {{ net: typeof netConnect, tls: typeof tlsConnect }} [connectors]
 */
export function createPinnedConnection(url, address, family, connectors = defaultConnectors) {
  const isHttps = url.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const port = url.port === '' ? defaultPort : Number(url.port);

  return function createConnection(_options, callback) {
    if (isHttps) {
      return connectors.tls({ host: address, family, port, servername: url.hostname }, callback);
    }
    return connectors.net({ host: address, family, port }, callback);
  };
}

/**
 * Issue one request to `address` (already validated) for `url`.
 *
 * Redirects are never followed here — `redirect: 'manual'` behaviour is the
 * caller's contract, and each hop must be re-validated before it is dialled.
 *
 * @param {URL} url            The target URL: path, Host, and TLS name.
 * @param {string} address     The validated IP literal to connect to.
 * @param {number} family      4 or 6.
 * @param {{ headers?: Record<string,string>, signal?: AbortSignal, connectors?: typeof defaultConnectors }} options
 * @returns {Promise<import('node:http').IncomingMessage>}
 */
export function pinnedFetch(url, address, family, options = {}) {
  const isHttps = url.protocol === 'https:';
  const send = isHttps ? httpsRequest : httpRequest;
  const createConnection = createPinnedConnection(
    url,
    address,
    family,
    options.connectors ?? defaultConnectors,
  );

  return new Promise((resolve, reject) => {
    const request = send(
      {
        // The authority stays the user-visible hostname, so Host, SNI, and
        // certificate checks are all unchanged by the pinning.
        host: url.hostname,
        port: url.port === '' ? undefined : Number(url.port),
        path: `${url.pathname}${url.search}`,
        method: options.method ?? 'GET',
        headers: options.headers ?? {},
        signal: options.signal,
        // Only the socket destination is redirected.
        createConnection,
      },
      resolve,
    );
    request.on('error', reject);
    request.end();
  });
}

/** Copy `url` with a different port; the test seam for per-address dials. */
function withPort(url, port) {
  const copy = new URL(url.href);
  copy.port = String(port);
  return copy;
}

/**
 * Try each validated address until one produces a response.
 *
 * A hostname may answer with several addresses and only some of them may be
 * reachable (IPv6 without a route is the common case). Falling back is safe
 * here *because every address in the list already passed the guard* — this is
 * not "retry until something works", it is "try the addresses that were all
 * cleared".
 *
 * A response — including an error status — is an answer and stops the loop. Only
 * a dial that produced no response at all falls through, so a 404 from the first
 * address is never masked by a second attempt.
 *
 * @param {URL} url
 * @param {readonly { address: string, family: number }[]} addresses
 * @param {object} [options] Forwarded to {@link pinnedFetch}.
 * @returns {Promise<import('node:http').IncomingMessage>}
 */
export async function pinnedFetchAny(url, addresses, options = {}) {
  if (addresses.length === 0) throw new Error('没有可连接的地址');
  const failures = [];
  for (const entry of addresses) {
    try {
      // `entry.port` is a test seam only: production callers pass addresses from
      // the guard, which carry no port, so the URL's port is used.
      const target = entry.port === undefined ? url : withPort(url, entry.port);
      return await pinnedFetch(target, entry.address, entry.family, options);
    } catch (error) {
      // A coded error means the dial itself failed (refused, unreachable,
      // timed out). Anything else is a programming fault and must surface.
      if (error?.code === undefined) throw error;
      failures.push(`${entry.address} (${error.code})`);
    }
  }
  throw new Error(`所有地址均无法连接：${failures.join('、')}`);
}
