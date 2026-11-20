import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { assertSafeTarget } from '../lib/ssrf-guard.js';
import { pinnedFetch } from '../lib/pinned-fetch.js';

/**
 * The DNS-rebinding defence, driven end to end.
 *
 * `assertSafeTarget` returns the address it validated, and `pinnedFetch` dials
 * exactly that address. The attack these tests model is a lookup whose answer
 * changes between the check and the connection — so the only trustworthy
 * assertion is "the address that was checked is the address that was dialled".
 */

/** A resolver stand-in that answers with `addresses` and records every call. */
function stubLookup(addresses) {
  const calls = [];
  const lookup = async (hostname, options) => {
    calls.push({ hostname, options });
    return addresses.map((address) => ({
      address,
      family: address.includes(':') ? 6 : 4,
    }));
  };
  return { lookup, calls };
}

/** Start a loopback server and return its port. */
async function localServer(handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}


test('an IP literal is returned as the address to dial', async () => {
  const target = await assertSafeTarget(new URL('http://1.1.1.1/sub'));
  assert.equal(target.address, '1.1.1.1');
  assert.equal(target.family, 4);
  // The full validated list is returned too, so a caller can fall back to another
  // cleared address without ever resolving the name again.
  assert.deepEqual(target.addresses, [{ address: '1.1.1.1', family: 4 }]);
});

test('an IPv6 literal is returned with family 6', async () => {
  const target = await assertSafeTarget(new URL('http://[2606:4700:4700::1111]/sub'));
  assert.equal(target.address, '2606:4700:4700::1111');
  assert.equal(target.family, 6);
});

test('a public hostname returns the validated address, not the name', async () => {
  const { lookup, calls } = stubLookup(['93.184.216.34']);
  const target = await assertSafeTarget(new URL('http://example.com/sub'), { lookup });
  assert.equal(target.address, '93.184.216.34');
  assert.equal(target.family, 4);
  assert.equal(calls.length, 1);
  // `all` matters: checking only the first answer would let a later one through.
  assert.equal(calls[0].options.all, true);
});

test('a hostname answering with an internal address is refused', async () => {
  const { lookup } = stubLookup(['93.184.216.34', '127.0.0.1']);
  await assert.rejects(
    () => assertSafeTarget(new URL('http://example.com/'), { lookup }),
    /禁止访问的内部地址/,
  );
});

test('every answer is judged, not just the first', async () => {
  // The internal record is last on purpose: a guard that only looked at
  // addresses[0] would pass this.
  const { lookup } = stubLookup(['1.1.1.1', '10.0.0.1']);
  await assert.rejects(
    () => assertSafeTarget(new URL('http://example.com/'), { lookup }),
    /禁止访问的内部地址/,
  );
});

test('an empty answer set is refused rather than treated as safe', async () => {
  const { lookup } = stubLookup([]);
  await assert.rejects(
    () => assertSafeTarget(new URL('http://example.com/'), { lookup }),
    /无法解析/,
  );
});

test('a failing resolver is refused', async () => {
  const lookup = async () => {
    throw new Error('ENOTFOUND');
  };
  await assert.rejects(
    () => assertSafeTarget(new URL('http://example.com/'), { lookup }),
    /无法解析/,
  );
});

test('blocked hostnames never reach the resolver', async () => {
  const { lookup, calls } = stubLookup(['1.1.1.1']);
  await assert.rejects(
    () => assertSafeTarget(new URL('http://localhost/'), { lookup }),
    /禁止访问的内部地址/,
  );
  assert.equal(calls.length, 0);
});

test('an unspecified IPv6 literal is refused (:: reaches loopback on Linux)', async () => {
  await assert.rejects(
    () => assertSafeTarget(new URL('http://[::]:8080/')),
    /禁止访问的内部地址/,
  );
});

test('rebinding: the guard\'s answer is the address actually dialled', async () => {
  // The attack: the name resolves to a public address when the guard asks, and
  // to loopback for anyone who resolves it again. A plain fetch() would take the
  // second answer; pinning means the second answer is never consulted.
  //
  // The dial is observed through an injected connector rather than by connecting
  // for real: a test that dials a public address has to wait for a timeout, which
  // makes it slow and dependent on the network it happens to run on.
  let lookups = 0;
  const rebindingLookup = async () => {
    lookups += 1;
    // First call: public. Every later call: loopback.
    return lookups === 1
      ? [{ address: '93.184.216.34', family: 4 }]
      : [{ address: '127.0.0.1', family: 4 }];
  };

  const url = new URL('http://rebind.example/admin');
  const target = await assertSafeTarget(url, { lookup: rebindingLookup });

  // The guard approved the public address and handed it back.
  assert.equal(target.address, '93.184.216.34');
  assert.equal(lookups, 1);

  // Record where the socket was told to go, then fail the dial so the test never
  // touches the network.
  const dialled = [];
  const connectors = {
    net: (options, callback) => {
      dialled.push(options);
      const error = new Error('dial observed');
      error.code = 'ETEST';
      callback(error);
      return { on() {}, destroy() {} };
    },
    tls: () => {
      throw new Error('tls connector must not be used for http');
    },
  };
  await pinnedFetch(url, target.address, target.family, { connectors }).catch(() => {});

  assert.equal(dialled.length, 1);
  // The decisive property: the socket went to the validated address, not to the
  // loopback answer a second resolution would have produced.
  assert.equal(dialled[0].host, '93.184.216.34');
  assert.equal(lookups, 1, 'pinnedFetch must not resolve the name again');
});

test('rebinding: a name that answers loopback is refused before any connection', async () => {
  const { server, port } = await localServer((req, res) => {
    res.writeHead(200);
    res.end('INTERNAL');
  });
  try {
    // Here the FIRST answer is already internal, which is the ordinary
    // "subscription points at the router" case.
    const internalLookup = async () => [{ address: '127.0.0.1', family: 4 }];
    await assert.rejects(
      () => assertSafeTarget(new URL(`http://evil.example:${port}/`), { lookup: internalLookup }),
      /禁止访问的内部地址/,
    );
  } finally {
    server.close();
  }
});
