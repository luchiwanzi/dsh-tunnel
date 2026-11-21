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

// ---- 含冒号但非 IP 的字符串不应被当作 IP 字面量跳过 ----
test('host:8080 之类的串仍会送去解析', async () => {
  const seen = [];
  const resolve = async (host) => { seen.push(host); return null; };
  await pinIpv6OnlyServers(
    [{ server: 'host:8080' }, { server: 'foo:bar' }],
    {},
    { resolve },
  );
  // 真正的 IPv4/IPv6 字面量才跳过；含冒号的普通串应进入解析队列。
  assert.deepEqual(seen.sort(), ['foo:bar', 'host:8080']);
});
// ============================================================
// 安全回归：钉入 hosts 的地址必须来自可信的解析结果
// 威胁模型：地址由插件自身 dns.lookup 产出，订阅方只提供域名。
// 解析层被污染时，内核可能被指向本机或内网。
// ============================================================

test('回环 / ULA / 链路本地 / IPv4-mapped 内网地址一律不钉入', async () => {
  const blocked = {
    'loopback.example': ['::1'],
    'ula.example': ['fd12:3456:789a::1'],
    'linklocal.example': ['fe80::1'],
    'mapped.example': ['::ffff:127.0.0.1'],
  };
  const { hosts, pinned } = await pinIpv6OnlyServers(
    Object.keys(blocked).map((server) => ({ server })),
    {},
    { resolve: fakeResolver(blocked) },
  );
  assert.deepEqual(pinned, []);
  assert.deepEqual(Object.keys(hosts), []);
});

test('带 zone 标识的链路本地地址同样不钉入', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'zone.example' }],
    {},
    { resolve: fakeResolver({ 'zone.example': ['fe80::1%eth0'] }) },
  );
  assert.deepEqual(pinned, []);
  assert.equal(hosts['zone.example'], undefined);
});

test('公网 IPv6 仍然正常钉入（安全过滤不误伤功能）', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'public6.example' }],
    {},
    { resolve: fakeResolver({ 'public6.example': ['2606:4700::1'] }) },
  );
  assert.equal(hosts['public6.example'], '2606:4700::1');
  assert.equal(pinned.length, 1);
});

// ---- 混合应答：安全过滤只影响"挑哪个地址"，不能影响"是否双栈"的判定 ----
// 否则整条记录被丢弃，本来可用的纯 IPv6 节点反而连不上。
test('混合应答（内网 IPv6 + 公网 IPv6）挑出公网地址', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'mixed1.example' }],
    {},
    { resolve: fakeResolver({ 'mixed1.example': ['::1', '2606:4700::3333'] }) },
  );
  assert.equal(hosts['mixed1.example'], '2606:4700::3333');
  assert.deepEqual(pinned, [{ server: 'mixed1.example', address: '2606:4700::3333' }]);
});

test('混合应答（无法解析的串 + 公网 IPv6）挑出公网地址', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'mixed2.example' }],
    {},
    { resolve: fakeResolver({ 'mixed2.example': ['host:8080', '2606:4700::4444'] }) },
  );
  assert.equal(hosts['mixed2.example'], '2606:4700::4444');
  assert.deepEqual(pinned, [{ server: 'mixed2.example', address: '2606:4700::4444' }]);
});

test('混合应答（真正有 IPv4 答案）不钉入', async () => {
  const { hosts, pinned } = await pinIpv6OnlyServers(
    [{ server: 'mixed3.example' }],
    {},
    { resolve: fakeResolver({ 'mixed3.example': ['104.16.1.1', '2606:4700::5555'] }) },
  );
  assert.deepEqual(pinned, []);
  assert.equal(hosts['mixed3.example'], undefined);
});
