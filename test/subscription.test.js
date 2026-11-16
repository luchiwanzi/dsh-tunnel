import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSubscription, parseUserinfo } from '../lib/subscription.js';

// 基础工具：把一个 URI 节点包成订阅文本
function uriList(...uris) {
  return uris.join('\n');
}

test('parseUserinfo 解析合法头部', () => {
  const info = parseUserinfo('upload=1000; download=2000; total=3000; expire=1700000000');
  assert.deepEqual(info, { upload: 1000, download: 2000, total: 3000, expire: 1700000000 });
});

test('parseUserinfo 忽略非法键和负数', () => {
  const info = parseUserinfo('upload=-1; foo=123; total=500');
  assert.deepEqual(info, { total: 500 });
});

test('parseUserinfo 空值返回 null', () => {
  assert.equal(parseUserinfo(''), null);
  assert.equal(parseUserinfo(null), null);
});

test('解析 SS 节点', () => {
  const b64 = Buffer.from('aes-128-gcm:secret123@example.com:8388').toString('base64');
  const uri = 'ss://' + b64 + '#我的节点';
  const result = parseSubscription(uriList(uri));
  assert.equal(result.nodes.length, 1);
  const node = result.nodes[0];
  assert.equal(node.type, 'ss');
  assert.equal(node.server, 'example.com');
  assert.equal(node.port, 8388);
  assert.equal(node.cipher, 'aes-128-gcm');
  assert.equal(node.password, 'secret123');
  assert.equal(node.name, '我的节点');
});

test('解析 trojan 节点并默认端口 443', () => {
  const uri = 'trojan://password@example.com#trojan-node';
  const result = parseSubscription(uriList(uri));
  const node = result.nodes[0];
  assert.equal(node.type, 'trojan');
  assert.equal(node.port, 443);
  assert.equal(node.password, 'password');
});

test('解析 socks5 节点', () => {
  const uri = 'socks5://user:pass@example.com:1080#socks';
  const result = parseSubscription(uriList(uri));
  const node = result.nodes[0];
  assert.equal(node.type, 'socks5');
  assert.equal(node.username, 'user');
  assert.equal(node.password, 'pass');
});

test('解析 http 节点默认端口', () => {
  const result = parseSubscription(uriList('http://example.com#http-node'));
  const node = result.nodes[0];
  assert.equal(node.type, 'http');
  assert.equal(node.port, 80);
});

test('解析 Clash YAML 的 proxies 列表', () => {
  const yaml = [
    'proxies:',
    '  - name: node1',
    '    type: ss',
    '    server: example.com',
    '    port: 443',
    '    cipher: aes-256-gcm',
    '    password: pass123',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.equal(result.format, 'clash');
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].name, 'node1');
});

test('跳过缺少必要字段的节点', () => {
  const yaml = [
    'proxies:',
    '  - name: bad',
    '    type: ss',
    '    server: example.com',
    '  - name: good',
    '    type: ss',
    '    server: example.com',
    '    port: 443',
    '    cipher: aes-256-gcm',
    '    password: pass',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].name, 'good');
  assert.ok(result.warnings.some((w) => w.includes('缺少必要字段')));
});

test('skip-cert-verify 节点被标记为 insecure', () => {
  const yaml = [
    'proxies:',
    '  - name: insecure-node',
    '    type: vmess',
    '    server: example.com',
    '    port: 443',
    '    uuid: abc',
    '    tls: true',
    '    skip-cert-verify: true',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].insecure, true);
  assert.ok(result.warnings.some((w) => w.includes('证书校验')));
});

test('正常节点 insecure 为 false', () => {
  const yaml = [
    'proxies:',
    '  - name: secure-node',
    '    type: ss',
    '    server: example.com',
    '    port: 443',
    '    cipher: aes-256-gcm',
    '    password: pass',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.equal(result.nodes[0].insecure, false);
});

test('保留 Clash hosts 映射', () => {
  const yaml = [
    'hosts:',
    '  "fake.example": "real.example"',
    'proxies:',
    '  - name: n',
    '    type: ss',
    '    server: fake.example',
    '    port: 443',
    '    cipher: aes-256-gcm',
    '    password: p',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.deepEqual(result.hosts, { 'fake.example': 'real.example' });
});

test('hosts 过滤原型污染键', () => {
  const yaml = [
    'hosts:',
    '  "__proto__": "evil"',
    '  "constructor": "evil"',
    '  "ok": "good"',
    'proxies:',
    '  - name: n',
    '    type: ss',
    '    server: ok',
    '    port: 443',
    '    cipher: aes-256-gcm',
    '    password: p',
  ].join('\n');
  const result = parseSubscription(yaml);
  assert.deepEqual(result.hosts, { ok: 'good' });
});

test('空内容抛出异常', () => {
  assert.throws(() => parseSubscription(''), /配置内容为空/);
  assert.throws(() => parseSubscription('   '), /配置内容为空/);
});

test('无法识别的格式抛出异常', () => {
  assert.throws(() => parseSubscription('this is not a subscription'), /无法识别内容格式/);
});

test('端口范围校验', () => {
  const bad = uriList('socks5://example.com:99999#bad');
  assert.throws(() => parseSubscription(bad), /无法识别内容格式|没有可用节点/);
});