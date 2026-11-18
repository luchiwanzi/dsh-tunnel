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

/** Servers resolved per connection attempt; subscriptions can carry hundreds. */
const MAX_RESOLVED_SERVERS = 40;
/** Parallel lookups; keeps the connect step fast without hammering the resolver. */
const LOOKUP_CONCURRENCY = 4;
const LOOKUP_TIMEOUT_MS = 4_000;

function isIpLiteral(value) {
  return value.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

function hasOwn(target, key) {
  return Object.prototype.hasOwnProperty.call(target, key);
}

function isIpv6(address) {
  return typeof address === 'string' && address.includes(':');
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
      // Any IPv4 answer means the core can resolve this server on its own.
      if (addresses.some((entry) => !isIpv6(entry?.address))) continue;
      const ipv6 = addresses.find((entry) => isIpv6(entry?.address));
      if (ipv6 === undefined) continue;
      hosts[server] = ipv6.address;
      pinned.push({ server, address: ipv6.address });
    }
  });
  await Promise.all(workers);

  return { hosts, pinned };
}

/** Human-readable note appended to the subscription warnings. */
export function describePinned(pinned) {
  if (!Array.isArray(pinned) || pinned.length === 0) return '';
  const names = pinned.map((entry) => entry.server).join('、');
  return '已为 ' + pinned.length + ' 个纯 IPv6 节点固定解析地址（' + names + '）';
}
