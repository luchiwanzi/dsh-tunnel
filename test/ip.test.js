import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isBlockedIp,
  isBlockedHostname,
  parseIpv4,
  BLOCKED_CIDRS,
  BLOCKED_CIDRS_V6,
  BLOCKED_HOSTS,
} from '../lib/ip.js';

// ---- IPv4 私有 / 保留网段 ----
test('拦截 IPv4 回环地址', () => {
  assert.equal(isBlockedIp('127.0.0.1'), true);
  assert.equal(isBlockedIp('127.255.255.255'), true);
});

test('拦截 IPv4 私有网段', () => {
  assert.equal(isBlockedIp('10.0.0.1'), true);
  assert.equal(isBlockedIp('172.16.0.1'), true);
  assert.equal(isBlockedIp('172.31.255.255'), true);
  assert.equal(isBlockedIp('192.168.1.1'), true);
});

test('拦截云元数据与链路本地地址', () => {
  assert.equal(isBlockedIp('169.254.169.254'), true);
  assert.equal(isBlockedIp('100.64.0.1'), true);
  assert.equal(isBlockedIp('0.0.0.0'), true);
});

test('放行公网 IPv4 地址', () => {
  assert.equal(isBlockedIp('8.8.8.8'), false);
  assert.equal(isBlockedIp('1.1.1.1'), false);
  assert.equal(isBlockedIp('172.15.0.1'), false);
  assert.equal(isBlockedIp('172.32.0.1'), false);
  assert.equal(isBlockedIp('11.0.0.1'), false);
});

// ---- IPv6 私有 / 保留网段 ----
test('拦截 IPv6 回环 ::1', () => {
  assert.equal(isBlockedIp('::1'), true);
  assert.equal(isBlockedIp('0:0:0:0:0:0:0:1'), true);
});

test('拦截未指定地址 ::（全零）—— 连接它会落到本机', () => {
  // 回归：isBlockedIpv6 曾只判 ::1，漏掉全零地址。Linux 上 connect 到 :: 会
  // 落到回环接口，于是 http://[::]:port/ 可以打穿内网；Windows 上该连接失败，
  // 但判定必须与平台无关。
  assert.equal(isBlockedIp('::'), true);
  assert.equal(isBlockedIp('0:0:0:0:0:0:0:0'), true);
  assert.equal(isBlockedIp('0000:0000:0000:0000:0000:0000:0000:0000'), true);
});

test('拦截 IPv6 链路本地 fe80::/10', () => {
  assert.equal(isBlockedIp('fe80::1'), true);
  assert.equal(isBlockedIp('fe80::aabb:ccdd'), true);
  assert.equal(isBlockedIp('febf::1'), true);
});

test('放行 fec0::（已废弃的 site-local，不在 fe80::/10）', () => {
  assert.equal(isBlockedIp('fec0::1'), false);
});

test('拦截 IPv6 私有 ULA fc00::/7', () => {
  assert.equal(isBlockedIp('fc00::1'), true);
  assert.equal(isBlockedIp('fd00:ec2::254'), true);
  assert.equal(isBlockedIp('fdff::1'), true);
});

test('放行 fe00::（不在 fc00::/7 内）', () => {
  assert.equal(isBlockedIp('fe00::1'), false);
});

test('放行公网 IPv6 地址', () => {
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false);
  assert.equal(isBlockedIp('2001:db8::1'), false);
});

// ---- IPv4-mapped IPv6 ----
// 注意：assertSafeTarget 传入的是 URL.hostname，Node 已把点分十进制
// 规范化为纯 hextet 形式（如 ::ffff:169.254.169.254 -> ::ffff:a9fe:a9fe）。
test('拦截 IPv4-mapped 的私有 / 元数据地址', () => {
  assert.equal(isBlockedIp('::ffff:a9fe:a9fe'), true);   // 169.254.169.254
  assert.equal(isBlockedIp('::ffff:7f00:1'), true);     // 127.0.0.1
  assert.equal(isBlockedIp('::ffff:a00:1'), true);      // 10.0.0.1
  assert.equal(isBlockedIp('::ffff:c0a8:101'), true);   // 192.168.1.1
  assert.equal(isBlockedIp('::ffff:ac10:1'), true);     // 172.16.0.1
});

test('放行 IPv4-mapped 的公网地址', () => {
  assert.equal(isBlockedIp('::ffff:808:808'), false);   // 8.8.8.8
});

// ---- 非法输入 ----
test('非法 IPv4/IPv6 返回 false（不拦截，交由外层 URL 解析拒绝）', () => {
  assert.equal(isBlockedIp('not-an-ip'), false);
  assert.equal(isBlockedIp('999.999.999.999'), false);
  assert.equal(isBlockedIp('::zzzz'), false);
  assert.equal(isBlockedIp('1:2:3:4:5:6:7:zzzz'), false);
});

// ---- parseIpv4 ----
test('parseIpv4 正确解析且拒绝非法输入', () => {
  assert.notEqual(parseIpv4('127.0.0.1'), null);
  assert.equal(parseIpv4('999.1.1.1'), null);
  assert.equal(parseIpv4('1.2.3'), null);
  assert.equal(parseIpv4('1.2.3.4.5'), null);
});

// ---- 主机名 ----
test('拦截特殊主机名', () => {
  assert.equal(isBlockedHostname('localhost'), true);
  assert.equal(isBlockedHostname('metadata.google.internal'), true);
  assert.equal(isBlockedHostname('example.com'), false);
});

test('BLOCKED_HOSTS 导出为 Set 且包含元数据域名', () => {
  assert.ok(BLOCKED_HOSTS instanceof Set);
  assert.ok(BLOCKED_HOSTS.has('metadata.google.internal'));
});
// ---- 规则清单与实现一致性 ----
// BLOCKED_CIDRS_V6 是给人读的说明，isBlockedIpv6 用位测试实现同一组规则。
// 这两处一旦漂移，说明数组就变成了误导人的死配置 —— 这条测试把它们钉在一起。
test('BLOCKED_CIDRS_V6 列出的每个网段，实现都真的拦截', () => {
  // 每个 CIDR 取一个代表地址，逐个验证实现会拦截。
  const samples = [
    ['::/128', '::'],
    ['::1/128', '::1'],
    ['fc00::/7', 'fc00::1'],
    ['fc00::/7', 'fd00:ec2::254'],
    ['fe80::/10', 'fe80::1'],
    ['::ffff:0:0/96', '::ffff:127.0.0.1'],
  ];
  for (const [cidr, address] of samples) {
    assert.ok(
      BLOCKED_CIDRS_V6.includes(cidr),
      `${cidr} 应出现在 BLOCKED_CIDRS_V6 中`,
    );
    assert.equal(isBlockedIp(address), true, `${address}（${cidr}）应被拦截`);
  }
});

test('BLOCKED_CIDRS 只含 IPv4 条目（IPv6 走单独的清单）', () => {
  // 旧实现把 ::1/128 等塞进 BLOCKED_CIDRS，而 isBlockedIpv4 只读含 '.' 的项，
  // 于是它们从不生效。分开两个清单后，这条测试防止有人再把两族混在一起。
  for (const cidr of BLOCKED_CIDRS) {
    assert.ok(cidr.includes('.'), `BLOCKED_CIDRS 不应出现 IPv6 条目：${cidr}`);
  }
});
