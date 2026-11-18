/**
 * Node-address resolution for IPv6-only proxy servers.
 *
 * The generated mihomo configuration pins `ipv6: false`, which makes the core
 * refuse to resolve a proxy server that only publishes AAAA records, failing
 * with "dns resolve failed: couldn't find ip". A bare URI subscription has no
 * way to express a host override, so a server reachable over IPv6 only can
 * never connect.
 *
 * This module resolves each proxy server once and pins the IPv6 answer through
 * the generated `hosts` map, which the core honours before any DNS lookup. The
 * core therefore keeps `ipv6: false` for ordinary traffic and only ever dials a
 * literal address for the proxy server itself.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isBlockedIp } from './ip.js';

/** Servers resolved per connection attempt; subscriptions can carry hundreds. */
const MAX_RESOLVED_SERVERS = 40;
/** Parallel lookups; keeps the connect step fast without hammering the resolver. */
const LOOKUP_CONCURRENCY = 4;
const LOOKUP_TIMEOUT_MS = 4_000;
/** Bound on how many server names describePinned() prints into one log line. */
const MAX_NAMED_IN_NOTE = 8;

function isIpLiteral(value) {
  // Use the platform's own IP classifier so that strings like `host:8080` or
  // `foo:bar` (which merely contain a colon) are NOT mistaken for IPv6 and
  // skipped. Only genuine IPv4/IPv6 literals are exempt from DNS resolution.
  return typeof value === 'string' && isIP(value) !== 0;
}

function hasOwn(target, key) {
  return Object.prototype.hasOwnProperty.call(target, key);
}

/**
 * Strip an IPv6 zone identifier, e.g. `fe80::1%eth0` -> `fe80::1`.
 *
 * isBlockedIp() parses the hextets strictly, so a zone suffix makes it report
 * "not blocked". Stripping the zone first keeps the link-local check effective.
 */
function withoutZone(address) {
  const index = address.indexOf('%');
  return index === -1 ? address : address.slice(0, index);
}

/** True for a real IPv6 literal. A zone identifier is tolerated. */
function isIpv6Address(address) {
  return typeof address === 'string' && isIP(withoutZone(address)) === 6;
}

/** True for a pin-safe address: real IPv6 that is not loopback, private or link-local. */
function isPinnable(address) {
  if (!isIpv6Address(address)) return false;
  return !isBlockedIp(withoutZone(address));
}

/** Keep a resolved address string usable as a hosts value. */
function normalizeAddress(value) {
  return typeof value === 'string' && value !== '' ? value : null;
}

/** Default resolver: all addresses for a host, with a bounded wait. */
async function defaultResolve(host) {
  let timer;
  try {
    return await Promise.race([
      lookup(host, { all: true, verbatim: true }),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), LOOKUP_TIMEOUT_MS);
      }),
    ]);
  } catch {
    return null;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Return a copy of `existingHosts` extended with an IPv6 pin for every proxy
 * server that resolves to IPv6 only. Servers that are IP literals, already
 * pinned, or that publish any IPv4 address are left untouched so the core keeps
 * its normal resolution path.
 *
 * @param {Array<Record<string, unknown>>} nodes
 * @param {Record<string, string>} existingHosts
 * @param {{resolve?: (host: string) => Promise<Array<{address: string}>|null>}} [options]
 * @returns {Promise<{hosts: Record<string, string>, pinned: Array<{server: string, address: string}>}>}
 */
export async function pinIpv6OnlyServers(nodes, existingHosts = {}, options = {}) {
  const resolve = typeof options.resolve === 'function' ? options.resolve : defaultResolve;
  const hosts = { ...existingHosts };
  const pinned = [];
  const seen = new Set();
  const queue = [];

  for (const node of Array.isArray(nodes) ? nodes : []) {
    const server = typeof node?.server === 'string' ? node.server.trim() : '';
    if (server === '__proto__') continue;
    if (server === '' || isIpLiteral(server)) continue;
    if (hasOwn(hosts, server) || seen.has(server)) continue;
    seen.add(server);
    queue.push(server);
    if (queue.length >= MAX_RESOLVED_SERVERS) break;
  }

  let cursor = 0;
  const workerCount = Math.min(LOOKUP_CONCURRENCY, queue.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (cursor < queue.length) {
      const server = queue[cursor];
      cursor += 1;
      const addresses = await resolve(server);
      if (!Array.isArray(addresses) || addresses.length === 0) continue;
      const resolved = addresses
        .map((entry) => normalizeAddress(entry?.address))
        .filter((address) => address !== null);
      // Only a real IPv4 answer means the core can resolve this server itself.
      // Testing for IPv4 - rather than for "not IPv6" - keeps an unparseable
      // answer from being mistaken for a usable IPv4 route and discarding the
      // whole record, which would drop a legitimate IPv6-only server.
      if (resolved.some((address) => isIP(withoutZone(address)) === 4)) continue;
      // Never pin an address pointing back into the local host or a private
      // range: the answer came from DNS, not from the subscription, so a
      // poisoned resolver must not be able to steer the core at ::1.
      const ipv6 = resolved.find((address) => isPinnable(address));
      if (ipv6 === undefined) continue;
      hosts[server] = ipv6;
      pinned.push({ server, address: ipv6 });
    }
  });
  await Promise.all(workers);

  return { hosts, pinned };
}

/** Human-readable note appended to the subscription warnings. */
export function describePinned(pinned) {
  if (!Array.isArray(pinned) || pinned.length === 0) return '';
  const servers = pinned
    .map((entry) => entry?.server)
    .filter((server) => typeof server === 'string' && server !== '');
  const names = servers.slice(0, MAX_NAMED_IN_NOTE).join('、');
  const suffix = servers.length > MAX_NAMED_IN_NOTE
    ? ' 等 ' + servers.length + ' 个节点'
    : '';
  return '已为 ' + pinned.length + ' 个纯 IPv6 节点固定解析地址（' + names + suffix + '）';
}
