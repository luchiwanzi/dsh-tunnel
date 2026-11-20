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
import { connect as netConnect, isIP } from 'node:net';
import { connect as tlsConnect } from 'node:tls';

/** Default socket factories; tests inject stand-ins to inspect the dial. */
export const defaultConnectors = { net: netConnect, tls: tlsConnect };

/**
 * How long one address may take before the next one is tried.
 *
 * An address family with no route (IPv6 on an IPv4-only network) does not fail
 * quickly — it hangs. Without a per-attempt bound, a hostname that answers with
 * both families would spend the caller's whole budget on the unreachable ones and
 * time out even though a reachable address was in the list. This bound applies
 * per attempt; a reachable address still gets the caller's full `signal` budget.
 */
export const PER_ADDRESS_DIAL_TIMEOUT_MS = 3000;

/**
 * The TLS server name for `url`, or `undefined` when there is none to set.
 *
 * `URL.hostname` keeps the brackets around an IPv6 literal
 * (`"[2606:4700::1]"`), which is not a name in any form, and an IPv4 literal is
 * an address too. Both return `undefined` so the caller omits SNI instead of
 * handing Node an invalid value (RFC 6066; Node warns with DEP0123).
 *
 * @param {URL} url
 * @returns {string | undefined}
 */
export function tlsServerName(url) {
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (host === '') return undefined;
  if (isIP(host) !== 0) return undefined;
  return host;
}

/**
 * A `createConnection` that dials `address` while presenting `url`'s identity.
 *
 * @param {URL} url
 * @param {string} address Already validated by the SSRF guard.
 * @param {number} family 4 or 6.
 * @param {{ net: typeof netConnect, tls: typeof tlsConnect }} [connectors]
 * @param {AbortSignal} [signal] Abandons the dial; `createConnection` is not
 *   given the request's signal, so it is threaded in explicitly.
 */
export function createPinnedConnection(
  url,
  address,
  family,
  connectors = defaultConnectors,
  signal,
) {
  const isHttps = url.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const port = url.port === '' ? defaultPort : Number(url.port);

  return function createConnection(_options, callback) {
    let settled = false;
    const settle = (error) => {
      if (settled) return;
      settled = true;
      callback(error);
    };

    const socket = isHttps
      ? connectors.tls(pinnedTlsOptions(url, address, family, port), settle)
      : connectors.net({ host: address, family, port }, settle);

    if (signal !== undefined) {
      const onAbort = () => {
        socket?.destroy?.();
        const reason = signal.reason;
        const error = reason instanceof Error ? reason : new Error('The operation was aborted');
        if (error.code === undefined) error.code = 'ABORT_ERR';
        settle(error);
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    return socket;
  };
}

/** The TLS options for a pinned dial; SNI is omitted for an IP literal. */
function pinnedTlsOptions(url, address, family, port) {
  const options = { host: address, family, port };
  const servername = tlsServerName(url);
  if (servername !== undefined) options.servername = servername;
  return options;
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
    options.signal,
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
        // Only the socket destination is redirected.
        createConnection,
      },
      resolve,
    );
    // `createConnection` is not given the request's signal, and aborting after
    // the request has started does not reject its promise — a dial that never
    // completes would simply hang. The bound is therefore applied as a race
    // against a timer: that holds for every socket implementation, real or
    // injected, instead of depending on which events a particular socket emits.
    if (options.dialTimeoutMs !== undefined) {
      const timer = setTimeout(() => {
        const error = new Error('address attempt timed out');
        error.code = 'ETIMEDOUT';
        request.destroy();
        reject(error);
      }, options.dialTimeoutMs);
      // Do not keep the process alive just for this timer.
      timer.unref?.();
      const clear = () => clearTimeout(timer);
      request.once('response', clear);
      request.once('error', clear);
      request.once('close', clear);
    }
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
 * Errors that mean "this address could not be dialled", so another one may work.
 *
 * Everything else — a TLS handshake failure, a certificate mismatch — is not
 * about the address being unreachable. Retrying it against a sibling address is
 * pointless (they all present the same certificate) and it buries the real
 * cause, so those errors are raised as they are.
 */
const DIAL_FAILURE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'EPIPE',
  'ABORT_ERR',
]);

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
 * @param {readonly { address: string, family: number, port?: number }[]} addresses
 * @param {object} [options] Forwarded to {@link pinnedFetch}.
 * @returns {Promise<import('node:http').IncomingMessage>}
 */
export async function pinnedFetchAny(url, addresses, options = {}) {
  if (addresses.length === 0) throw new Error('没有可连接的地址');
  const callerSignal = options.signal;
  const failures = [];
  for (const entry of addresses) {
    const attempt = new AbortController();
    const onCallerAbort = () => attempt.abort(callerSignal?.reason);
    callerSignal?.addEventListener('abort', onCallerAbort, { once: true });
    const timer = setTimeout(() => {
      const timeout = new Error('address attempt timed out');
      timeout.code = 'ETIMEDOUT';
      attempt.abort(timeout);
    }, PER_ADDRESS_DIAL_TIMEOUT_MS);
    try {
      // `entry.port` is a test seam only: production callers pass addresses from
      // the guard, which carry no port, so the URL's port is used.
      const target = entry.port === undefined ? url : withPort(url, entry.port);
      return await pinnedFetch(target, entry.address, entry.family, {
        ...options,
        signal: attempt.signal,
        dialTimeoutMs: options.dialTimeoutMs ?? PER_ADDRESS_DIAL_TIMEOUT_MS,
      });
    } catch (error) {
      // The caller cancelling is not a per-address failure: stop the chain.
      if (callerSignal?.aborted === true) throw callerSignal.reason ?? error;
      const code = error?.code;
      // A TLS/certificate/handshake failure (EPROTO, CERT_*, ERR_TLS_*, or a
      // verify error) says nothing about reachability: surface it unchanged so
      // the user sees why the connection was refused.
      if (typeof code !== 'string' || !DIAL_FAILURE_CODES.has(code)) throw error;
      failures.push(`${entry.address} (${code})`);
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', onCallerAbort);
    }
  }
  throw new Error(`所有地址均无法连接：${failures.join('、')}`);
}
