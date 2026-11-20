/**
 * SSRF guard for subscription URLs.
 *
 * Two properties matter here, and they are separate:
 *
 * 1. **What is refused.** Loopback, private, link-local, reserved, cloud-metadata
 *    addresses and a few special hostnames. An IP literal is judged directly; a
 *    hostname is resolved and *every* answer is judged.
 * 2. **What is connected.** The address this module returns is the address the
 *    caller must dial. Checking a name and then letting `fetch()` resolve it
 *    again is not a check at all: an attacker-controlled record can answer with
 *    a public address during the check and loopback a moment later. That is DNS
 *    rebinding, and the only real defence is to keep the validated address.
 *
 * The `lookup` seam exists so tests can drive both halves — a rebinding attack
 * is exactly a lookup whose answer changes between two calls.
 */

import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isBlockedHostname, isBlockedIp, parseIpv4 } from './ip.js';

/**
 * Resolve a subscription URL's target and refuse it when it points inward.
 *
 * @param {URL} url
 * @param {{ lookup?: typeof dnsLookup }} [options]
 *   `lookup` defaults to `node:dns/promises`; tests inject a controllable one.
 * @returns {Promise<{ address: string, family: number, addresses: { address: string, family: number }[] }>}
 *   `address`/`family` are the first validated target; `addresses` is the whole
 *   validated list, so a caller may fall back to another one without ever
 *   resolving the name again. Every entry in `addresses` has passed the guard.
 */
export async function assertSafeTarget(url, options = {}) {
  const lookup = options.lookup ?? dnsLookup;
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === '' || isBlockedHostname(host)) {
    throw new Error('订阅地址指向禁止访问的内部地址');
  }
  // An IP literal needs no resolution, and the literal itself is what gets
  // dialled.
  if (parseIpv4(host) !== null || host.includes(':')) {
    if (isBlockedIp(host)) throw new Error('订阅地址指向禁止访问的内部地址');
    const family = isIP(host) === 6 ? 6 : 4;
    return { address: host, family, addresses: [{ address: host, family }] };
  }
  // A hostname is resolved and every answer is judged: one internal answer
  // disqualifies the whole name, whatever order the resolver returns them in.
  let addresses;
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new Error('订阅地址域名无法解析');
  }
  if (addresses.length === 0) throw new Error('订阅地址域名无法解析');
  if (addresses.some((entry) => isBlockedIp(entry.address))) {
    throw new Error('订阅地址解析到禁止访问的内部地址');
  }
  // Every record here passed the guard, so the caller may try them in order.
  const validated = addresses.map((entry) => ({ address: entry.address, family: entry.family }));
  const chosen = validated[0];
  return { address: chosen.address, family: chosen.family, addresses: validated };
}
