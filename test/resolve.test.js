import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describePinned, pinIpv6OnlyServers } from '../lib/resolve.js';

/** 确定性的假解析器：按表返回地址，避免测试依赖真实 DNS。 */
function fakeResolver(table) {
  return async (host) => {
    const entry = table[host];
    if (entry === undefined) return null;
    return entry.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
}

const IPV6_ONLY = { 'v6.example': ['2606:4700::1111'] };
const DUAL_STACK = { 'dual.example': ['203.0.113.9', '2606:4700::2222'] };
const IPV4_ONLY = { 'v4.example': ['198.51.100.5'] };

// ---- 纯 IPv6 节点被固定 ----
test('纯 IPv6 服务器写入 hosts', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'v6.example' }],
    {},
    { resolve: fakeResolver(IPV6_ONLY) },
  );
  assert.equal(hosts['v6.example'], '2606:4700::1111');
  assert.deepEqual(pinned, [{ server: 'v6.example', address: '2606:4700::1111' }]);
});

// ---- 双栈节点不动（核心自己能解析） ----
test('同时有 IPv4 的服务器保持原样', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'dual.example' }],
    {},
    { resolve: fakeResolver(DUAL_STACK) },
  );
  assert.equal(hosts['dual.example'], undefined);
  assert.deepEqual(pinned, []);
});

// ---- 只有 IPv4 的节点不动 ----
test('只有 IPv4 的服务器保持原样', async () => {
  const { pinned } = await pinIpv6OnlyServers([{ server: 'v4.example' }], {}, { resolve: fakeResolver(IPV4_ONLY) });
  assert.deepEqual(pinned, []);
});

// ---- 已有 hosts 不被覆盖 ----
test('保留已有的 hosts 映射', async () => {
  const resolve = async () => { throw new Error('不应被调用'); };
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'v6.example' }],
    { 'v6.example': '2001:db8::1' },
    { resolve },
  );
  assert.equal(hosts['v6.example'], '2001:db8::1');
  assert.deepEqual(pinned, []);
});

// ---- IP 字面量不解析 ----
test('跳过 IPv4 与 IPv6 字面量', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers([
    { server: '203.0.113.7' },
    { server: '2001:db8::1' },
  ], {}, { resolve: async () => { throw new Error('不应被调用'); } });
  assert.deepEqual(pinned, []);
  assert.deepEqual(Object.keys(hosts), []);
});

// ---- 无效输入 ----
test('容忍非数组节点与空 server', async () => {
  const noop = { resolve: async () => null };
  assert.deepEqual((await pinIpv6OnlyServers(null, {}, noop)).pinned, []);
  assert.deepEqual((await pinIpv6OnlyServers([{ server: '' }, null, {}], {}, noop)).pinned, []);
});

// ---- 解析失败/超时被忽略 ----
test('无法解析的服务器不写入 hosts', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'missing.example' }],
    {},
    { resolve: fakeResolver({}) },
  );
  assert.deepEqual(pinned, []);
  assert.equal(hosts['missing.example'], undefined);
});

// ---- 同一服务器只解析一次 ----
test('重复 server 只解析一次', async () => {
  let calls = 0;
  const resolve = async () => { calls += 1; return [{ address: '2606:4700::3333' }]; };
  await pinIpv6OnlyServers(
    [{ server: 'v6.example' }, { server: 'v6.example' }, { server: 'v6.example' }],
    {},
    { resolve },
  );
  assert.equal(calls, 1);
});

// ---- 原型键防护 ----
test('跳过 __proto__ server 名', async () => {
  const resolve = async () => { throw new Error('不应被调用'); };
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: '__proto__' }],
    {},
    { resolve },
  );
  assert.deepEqual(pinned, []);
  assert.deepEqual(Object.keys(hosts), []);
});

// ---- 畸形解析结果防护 ----
test('忽略空/未知地址的解析结果', async () => {
  const resolve = async () => [
    { address: '' },
    { address: null },
    {},
    { address: '2606:4700::4444' },
  ];
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'v6.example' }],
    {},
    { resolve },
  );
  assert.equal(hosts['v6.example'], '2606:4700::4444');
  assert.equal(pinned.length, 1);
});

// ---- 文案截断 ----
test('describePinned 截断超长列表', () => {
  const pinned = Array.from({ length: 10 }, (_, i) => ({ server: 'n' + i + '.example' }));
  const note = describePinned(pinned);
  assert.match(note, /n7\.example/);
  assert.doesNotMatch(note, /n8\.example/);
  assert.match(note, /等 10 个节点/);
});

// ---- 描述文案 ----
test('describePinned 文案', () => {
  assert.equal(describePinned([]), '');
  assert.equal(describePinned(null), '');
  assert.match(describePinned([{ server: 'a.example', address: '2001:db8::1' }]), /a\.example/);
});
