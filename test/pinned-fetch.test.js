import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { pinnedFetch, pinnedFetchAny } from '../lib/pinned-fetch.js';

/**
 * DNS rebinding: the guard resolves a hostname and checks the answers, then the
 * connection must go to *that* address. A plain `fetch()` resolves the name a
 * second time, so a record that changes between the two lookups lets a checked
 * public name land on loopback. These tests pin the connection instead.
 */

/** Start a local server and hand back its port. */
async function localServer(handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

/** Read a stream to a string. */
async function drain(stream) {
  let body = '';
  for await (const chunk of stream) body += chunk;
  return body;
}

test('pinnedFetch connects to the given address, not a fresh DNS answer', async () => {
  const { server, port } = await localServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('INTERNAL');
  });
  try {
    // The URL names a host that does not exist; the pinned address is what we
    // dial, so resolution never happens and the request still succeeds.
    const url = new URL(`http://rebind.invalid:${port}/secret`);
    const response = await pinnedFetch(url, '127.0.0.1', 4);
    assert.equal(response.statusCode, 200);
    assert.equal(await drain(response), 'INTERNAL');
  } finally {
    server.close();
  }
});

test('pinnedFetch preserves the original Host header', async () => {
  let seenHost = '';
  const { server, port } = await localServer((req, res) => {
    seenHost = req.headers.host;
    res.writeHead(200);
    res.end('ok');
  });
  try {
    const url = new URL(`http://subscription.example:${port}/nodes`);
    const response = await pinnedFetch(url, '127.0.0.1', 4);
    await drain(response);
    // Virtual hosting and subscription endpoints key on this; pinning must not
    // rewrite it to the IP.
    assert.equal(seenHost, `subscription.example:${port}`);
  } finally {
    server.close();
  }
});

test('pinnedFetch sends the path and query unchanged', async () => {
  let seenUrl = '';
  const { server, port } = await localServer((req, res) => {
    seenUrl = req.url;
    res.writeHead(200);
    res.end('ok');
  });
  try {
    const url = new URL(`http://host.example:${port}/sub/path?a=1&b=2`);
    const response = await pinnedFetch(url, '127.0.0.1', 4);
    await drain(response);
    assert.equal(seenUrl, '/sub/path?a=1&b=2');
  } finally {
    server.close();
  }
});

test('pinnedFetch does not follow redirects on its own', async () => {
  const { server, port } = await localServer((req, res) => {
    res.writeHead(302, { location: 'http://elsewhere.example/' });
    res.end();
  });
  try {
    const url = new URL(`http://host.example:${port}/`);
    const response = await pinnedFetch(url, '127.0.0.1', 4);
    // Manual redirection is the caller's contract: every hop is re-validated.
    assert.equal(response.statusCode, 302);
    assert.equal(response.headers.location, 'http://elsewhere.example/');
    response.resume();
  } finally {
    server.close();
  }
});

test('pinnedFetch forwards caller headers and keeps the Host it was given', async () => {
  let seen = null;
  const { server, port } = await localServer((req, res) => {
    seen = req.headers;
    res.writeHead(200);
    res.end('ok');
  });
  try {
    const url = new URL(`http://host.example:${port}/`);
    const response = await pinnedFetch(url, '127.0.0.1', 4, {
      headers: { 'user-agent': 'clash.meta/1.19.33', accept: 'text/yaml' },
    });
    await drain(response);
    assert.equal(seen['user-agent'], 'clash.meta/1.19.33');
    assert.equal(seen.accept, 'text/yaml');
    assert.equal(seen.host, `host.example:${port}`);
  } finally {
    server.close();
  }
});

test('pinnedFetch rejects when the address refuses the connection', async () => {
  // Port 1 on loopback: nothing listens, so the dial fails rather than silently
  // falling back to a fresh resolution.
  const url = new URL('http://host.example:1/');
  await assert.rejects(() => pinnedFetch(url, '127.0.0.1', 4));
});
test('pinnedFetch keeps Host and authority consistent (Node rejects a mismatch)', async () => {
  let seenHost = '';
  const { server, port } = await localServer((req, res) => {
    seenHost = req.headers.host;
    res.writeHead(200);
    res.end('ok');
  });
  try {
    // Regression: an earlier implementation rewrote options.host to the IP while
    // leaving the Host header as the hostname, and Node refused the request with
    // ERR_INVALID_ARG_VALUE ("Host in options.headers must match the request
    // authority"). Redirecting the socket instead keeps both consistent.
    const url = new URL(`http://real-name.example:${port}/`);
    const response = await pinnedFetch(url, '127.0.0.1', 4);
    await drain(response);
    assert.equal(response.statusCode, 200);
    assert.equal(seenHost, `real-name.example:${port}`);
  } finally {
    server.close();
  }
});
test('pinnedFetchAny falls back to the next validated address when one is unreachable', async () => {
  const { server, port } = await localServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('REACHED');
  });
  try {
    // The first entry dials a port nothing listens on, so the dial fails with a
    // coded error and the chain moves on. The second is the live server.
    const url = new URL(`http://multi.example:${port}/`);
    const response = await pinnedFetchAny(
      url,
      [
        { address: '127.0.0.1', family: 4, port: 1 },
        { address: '127.0.0.1', family: 4 },
      ],
      { signal: AbortSignal.timeout(1500) },
    );
    assert.equal(response.statusCode, 200);
    let body = '';
    for await (const chunk of response) body += chunk;
    assert.equal(body, 'REACHED');
  } finally {
    server.close();
  }
});

test('pinnedFetchAny tries every address and reports all failures', async () => {
  const url = new URL('http://dead.example:1/');
  const error = await pinnedFetchAny(
    url,
    [
      { address: '127.0.0.1', family: 4 },
      { address: '127.0.0.2', family: 4 },
    ],
    { signal: AbortSignal.timeout(1500) },
  ).catch((caught) => caught);
  assert.ok(error instanceof Error);
  assert.match(error.message, /所有地址均无法连接/);
  // Both addresses are named, so a support report can tell which were tried.
  assert.match(error.message, /127\.0\.0\.1/);
  assert.match(error.message, /127\.0\.0\.2/);
});

test('pinnedFetchAny refuses an empty address list', async () => {
  await assert.rejects(
    () => pinnedFetchAny(new URL('http://x.example/'), []),
    /没有可连接的地址/,
  );
});

test('pinnedFetchAny does not fall back when a response was received', async () => {
  let hits = 0;
  const { server, port } = await localServer((req, res) => {
    hits += 1;
    // A 404 is still an answer; it must not be masked by a second attempt.
    res.writeHead(404);
    res.end('nope');
  });
  try {
    const url = new URL(`http://answer.example:${port}/`);
    // Both entries point at the same live server, so a fallback would show up as
    // a second hit. One request is the contract.
    const response = await pinnedFetchAny(url, [
      { address: '127.0.0.1', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    assert.equal(response.statusCode, 404);
    response.resume();
    assert.equal(hits, 1, 'a received response must stop the fallback chain');
  } finally {
    server.close();
  }
});

test('https pinning keeps SNI and certificate validation on the original hostname', async () => {
  // The connector seam lets us assert what TLS would be asked to verify without
  // standing up a certificate authority.
  const dialled = [];
  const connectors = {
    net: () => {
      throw new Error('net connector must not be used for https');
    },
    tls: (options, callback) => {
      dialled.push(options);
      // Fail the handshake deliberately: this test is about the parameters.
      const error = new Error('handshake skipped');
      error.code = 'ETEST';
      callback(error);
      return { on() {}, destroy() {} };
    },
  };

  const url = new URL('https://subscription.example/sub');
  await pinnedFetch(url, '93.184.216.34', 4, { connectors }).catch(() => {});

  assert.equal(dialled.length, 1);
  const options = dialled[0];
  // The socket goes to the validated IP...
  assert.equal(options.host, '93.184.216.34');
  assert.equal(options.family, 4);
  assert.equal(options.port, 443);
  // ...while SNI and the certificate check stay on the name the user typed.
  assert.equal(options.servername, 'subscription.example');
});

test('an http URL never uses the TLS connector', async () => {
  const used = [];
  const connectors = {
    net: (options, callback) => {
      used.push({ kind: 'net', options });
      const error = new Error('skipped');
      error.code = 'ETEST';
      callback(error);
      return { on() {}, destroy() {} };
    },
    tls: () => {
      used.push({ kind: 'tls' });
      throw new Error('tls connector must not be used for http');
    },
  };
  await pinnedFetch(new URL('http://plain.example/x'), '1.1.1.1', 4, { connectors }).catch(() => {});
  assert.equal(used.length, 1);
  assert.equal(used[0].kind, 'net');
  assert.equal(used[0].options.host, '1.1.1.1');
  assert.equal(used[0].options.port, 80);
});
test('an IP-literal https URL omits SNI instead of setting an invalid name', async () => {
  const dialled = [];
  const connectors = {
    net: () => { throw new Error('net connector must not be used for https') },
    tls: (options, callback) => {
      dialled.push(options);
      const error = new Error('skipped');
      error.code = 'ETEST';
      callback(error);
      return { on() {}, destroy() {} };
    },
  };
  // RFC 6066 forbids an IP in SNI; Node warns (DEP0123) and will ignore it.
  await pinnedFetch(new URL('https://1.1.1.1/x'), '1.1.1.1', 4, { connectors }).catch(() => {});
  assert.equal(dialled.length, 1);
  assert.equal(dialled[0].servername, undefined);

  // An IPv6 literal keeps its brackets in URL.hostname, which is not a name either.
  dialled.length = 0;
  await pinnedFetch(new URL('https://[2606:4700::1]/x'), '2606:4700::1', 6, { connectors }).catch(() => {});
  assert.equal(dialled.length, 1);
  assert.equal(dialled[0].servername, undefined);
});

test('a named https URL still sets SNI', async () => {
  const dialled = [];
  const connectors = {
    net: () => { throw new Error('unused') },
    tls: (options, callback) => {
      dialled.push(options);
      const error = new Error('skipped');
      error.code = 'ETEST';
      callback(error);
      return { on() {}, destroy() {} };
    },
  };
  await pinnedFetch(new URL('https://sub.example/x'), '1.1.1.1', 4, { connectors }).catch(() => {});
  assert.equal(dialled[0].servername, 'sub.example');
});

test('a TLS handshake failure is surfaced, not retried as an unreachable address', async () => {
  // A certificate mismatch fails identically for every address of the name, so
  // retrying would bury the real cause. Only dial failures fall through.
  let attempts = 0;
  const connectors = {
    net: () => { throw new Error('unused') },
    tls: (options, callback) => {
      attempts += 1;
      const error = new Error('certificate has expired');
      error.code = 'CERT_HAS_EXPIRED';
      callback(error);
      return { on() {}, destroy() {} };
    },
  };
  const error = await pinnedFetchAny(
    new URL('https://bad.example/x'),
    [{ address: '1.1.1.1', family: 4 }, { address: '1.0.0.1', family: 4 }],
    { connectors },
  ).catch((caught) => caught);
  assert.equal(attempts, 1, 'a handshake failure must not be retried on the next address');
  assert.equal(error.code, 'CERT_HAS_EXPIRED', 'the original cause must survive');
  assert.doesNotMatch(error.message, /所有地址均无法连接/);
});

test('a dial failure still falls through to the next address', async () => {
  let attempts = 0;
  const connectors = {
    net: (options, callback) => {
      attempts += 1;
      const error = new Error('refused');
      error.code = 'ECONNREFUSED';
      callback(error);
      return { on() {}, destroy() {} };
    },
    tls: () => { throw new Error('unused') },
  };
  const error = await pinnedFetchAny(
    new URL('http://x.example/'),
    [{ address: '1.1.1.1', family: 4 }, { address: '1.0.0.1', family: 4 }],
    { connectors },
  ).catch((caught) => caught);
  assert.equal(attempts, 2, 'every address must be tried');
  assert.match(error.message, /所有地址均无法连接/);
});
test('an unroutable address is abandoned per-attempt, not at the caller timeout', async () => {
  // An address family with no route hangs instead of failing. Without a
  // per-attempt bound, a hostname with both families takes as long as every
  // unreachable address in turn — the whole fetch then times out even though a
  // reachable address was in the list.
  //
  // The connector only has to *not connect*: the wrapper itself turns the
  // per-attempt abort into a callback with an ABORT_ERR, which is what makes the
  // chain move on. A stub that connected instantly would never exercise it.
  let attempts = 0;
  const connectors = {
    net: () => {
      attempts += 1;
      // Never call back: the dial hangs, exactly like an unroutable address.
      return { on() {}, destroy() {} };
    },
    tls: () => { throw new Error('unused') },
  };
  const started = Date.now();
  await pinnedFetchAny(
    new URL('http://hang.example/'),
    [{ address: '2001:db8::1', family: 6 }, { address: '1.1.1.1', family: 4 }],
    { connectors },
  ).catch(() => {});
  // The first address must be abandoned on the per-attempt budget, so the second
  // one is reached well before any caller-level timeout.
  assert.equal(attempts, 2, 'the hanging address must not block the next one');
  assert.ok(Date.now() - started < 10_000, 'the chain must not wait out a caller timeout');
});
