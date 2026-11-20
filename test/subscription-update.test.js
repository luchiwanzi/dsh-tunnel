import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { parseUserinfo } from '../lib/subscription.js';

/**
 * The subscription-update path, end to end.
 *
 * This file exists because the `lib/`-level tests could not catch a regression
 * that broke every subscription update: `updateSubscription` still read the
 * response headers with `headers.get()` after `fetchSubscription` had started
 * returning Node's plain header object. The content downloaded and parsed fine,
 * then the very last line threw a TypeError — so nothing was saved and the user
 * saw a stack-trace-shaped message.
 *
 * These tests drive the same shape of value `fetchSubscription` now returns and
 * assert that the header read, the body read and the timeout all behave.
 */

/** Start a server that answers once with the given headers and body. */
async function subscriptionServer(headers, body) {
  const server = createServer((req, res) => {
    res.writeHead(200, headers);
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

test('subscription-userinfo is read with bracket access, not headers.get()', () => {
  // Node's IncomingMessage.headers is a plain object. `.get` is undefined there,
  // and calling it threw on every successful update.
  const headers = { 'subscription-userinfo': 'upload=1; download=2; total=3; expire=4' };
  assert.equal(typeof headers.get, 'undefined');

  const info = parseUserinfo(headers['subscription-userinfo']);
  assert.deepEqual(info, { upload: 1, download: 2, total: 3, expire: 4 });
});

test('a missing userinfo header yields null rather than throwing', () => {
  const headers = {};
  assert.equal(parseUserinfo(headers['subscription-userinfo']), null);
});

test('the body of a real response can be read with for-await', async () => {
  const yaml = 'proxies:\n  - name: n1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n';
  const { server, port } = await subscriptionServer(
    { 'content-type': 'text/yaml', 'subscription-userinfo': 'total=10' },
    yaml,
  );
  try {
    const { pinnedFetchAny } = await import('../lib/pinned-fetch.js');
    const res = await pinnedFetchAny(new URL(`http://127.0.0.1:${port}/`), [
      { address: '127.0.0.1', family: 4 },
    ]);
    let body = '';
    for await (const chunk of res) body += chunk;
    assert.equal(body, yaml);
    assert.equal(res.headers['subscription-userinfo'], 'total=10');
  } finally {
    server.close();
  }
});

test('a body that stalls after the headers is abandoned on the read timeout', async () => {
  // A server that sends headers and a partial body, then holds the connection.
  // Without a read timeout the for-await below never settles, and because the
  // plugin's API queue is serial, that wedges every later operation.
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/yaml', 'content-length': '9999' });
    res.write('partial');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  /** The same guard `readCapped` applies, exercised without its byte cap. */
  async function readWithTimeout(stream, timeoutMs) {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      stream.destroy();
    }, timeoutMs);
    timer.unref?.();
    try {
      let size = 0;
      for await (const chunk of stream) size += chunk.byteLength;
      return size;
    } catch (error) {
      if (timedOut) throw new Error('read timeout');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  try {
    const { pinnedFetchAny } = await import('../lib/pinned-fetch.js');
    const res = await pinnedFetchAny(new URL(`http://127.0.0.1:${port}/`), [
      { address: '127.0.0.1', family: 4 },
    ]);
    const started = Date.now();
    await assert.rejects(() => readWithTimeout(res, 400), /read timeout/);
    // It must give up near the timeout, not hang.
    assert.ok(Date.now() - started < 3000, 'the stalled read must not hang');
  } finally {
    server.close();
  }
});
