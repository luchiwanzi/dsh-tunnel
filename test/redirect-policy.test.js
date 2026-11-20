import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_REDIRECT_HOPS,
  normalizeForVisit,
  resolveRedirect,
} from '../lib/redirect-policy.js';

/**
 * Redirect policy is security-relevant: a subscription link is followed by hand
 * so every hop can be re-validated, which makes the loop itself the place where
 * a hostile server could hold the fetch open, downgrade transport, or pivot the
 * scheme. These tests pin each rule without touching the network.
 */

/** A visited set already holding `url`. */
function visitedWith(url) {
  return new Set([normalizeForVisit(new URL(url))]);
}

test('a plain redirect is followed', () => {
  const current = new URL('https://a.example/sub');
  const decision = resolveRedirect(current, 'https://b.example/next', visitedWith(current.href), 0);
  assert.equal(decision.action, 'follow');
  assert.equal(decision.url.href, 'https://b.example/next');
});

test('a relative Location is resolved against the current URL', () => {
  const current = new URL('https://a.example/dir/sub');
  const decision = resolveRedirect(current, '../other', visitedWith(current.href), 0);
  assert.equal(decision.action, 'follow');
  assert.equal(decision.url.href, 'https://a.example/other');
});

test('a missing or blank Location stops the chain', () => {
  const current = new URL('https://a.example/sub');
  assert.equal(resolveRedirect(current, undefined, new Set(), 0).action, 'stop');
  assert.equal(resolveRedirect(current, '   ', new Set(), 0).action, 'stop');
  assert.equal(resolveRedirect(current, '   ', new Set(), 0).reason, 'missing-location');
});

test('an unparsable Location stops the chain', () => {
  const current = new URL('https://a.example/sub');
  const decision = resolveRedirect(current, 'http://[bad', new Set(), 0);
  assert.equal(decision.action, 'stop');
  assert.equal(decision.reason, 'invalid-location');
});

test('the hop limit is enforced', () => {
  const current = new URL('https://a.example/sub');
  const atLimit = resolveRedirect(current, 'https://b.example/', new Set(), MAX_REDIRECT_HOPS);
  assert.equal(atLimit.action, 'stop');
  assert.equal(atLimit.reason, 'too-many-hops');
  // One hop before the limit still follows.
  const beforeLimit = resolveRedirect(current, 'https://b.example/', new Set(), MAX_REDIRECT_HOPS - 1);
  assert.equal(beforeLimit.action, 'follow');
});

test('non-http schemes are refused', () => {
  const current = new URL('https://a.example/sub');
  for (const location of ['file:///etc/passwd', 'data:text/plain,x', 'ftp://a.example/x']) {
    const decision = resolveRedirect(current, location, new Set(), 0);
    assert.equal(decision.action, 'stop', `${location} 应被拒绝`);
    assert.match(decision.reason, /^protocol-not-allowed:/);
  }
});

test('https to http downgrade is refused', () => {
  const current = new URL('https://a.example/sub');
  const decision = resolveRedirect(current, 'http://a.example/sub', new Set(), 0);
  assert.equal(decision.action, 'stop');
  assert.equal(decision.reason, 'downgrade-refused');
});

test('http to https upgrade is allowed', () => {
  const current = new URL('http://a.example/sub');
  const decision = resolveRedirect(current, 'https://a.example/sub', new Set(), 0);
  assert.equal(decision.action, 'follow');
});

test('a chain returning to a visited URL is a loop', () => {
  const current = new URL('https://a.example/second');
  const visited = visitedWith('https://a.example/first');
  const decision = resolveRedirect(current, 'https://a.example/first', visited, 1);
  assert.equal(decision.action, 'stop');
  assert.equal(decision.reason, 'redirect-loop');
});

test('cycle detection ignores cosmetic differences', () => {
  const current = new URL('https://a.example/second');
  // Same target as the visited entry, spelled differently: upper-case host,
  // explicit default port, and a fragment that never reaches the server.
  const visited = visitedWith('https://a.example/first');
  const decision = resolveRedirect(current, 'https://A.EXAMPLE:443/first#section', visited, 1);
  assert.equal(decision.action, 'stop');
  assert.equal(decision.reason, 'redirect-loop');
});

test('normalizeForVisit drops the fragment, lowercases the host, and elides default ports', () => {
  assert.equal(
    normalizeForVisit(new URL('https://A.Example:443/x#frag')),
    'https://a.example/x',
  );
  assert.equal(normalizeForVisit(new URL('http://a.example:80/x')), 'http://a.example/x');
  // A non-default port is part of the identity and must be kept.
  assert.equal(normalizeForVisit(new URL('https://a.example:8443/x')), 'https://a.example:8443/x');
});