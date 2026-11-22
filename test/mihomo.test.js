// mihomo.js 内核二进制 pin 校验的单元测试。
//
// 覆盖 verifyCoreBinary 的关键路径：有 pin 命中/不命中、无 pin 跳过（不读文件）、
// 读失败 fail-closed、错误信息含平台/路径/双 hash。platform/arch 可注入，
// 测试不依赖真实运行平台。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { verifyCoreBinary, CORE_VERSION } from '../lib/mihomo.js';

test('版本号仍是钉住的 v1.19.33', () => {
  assert.equal(CORE_VERSION, 'v1.19.33');
});

test('verifyCoreBinary：无 pin 平台跳过校验，且不读文件', async () => {
  // freebsd-x64 不在 PACKAGED_CORE_SHA256 里（插件不支持该平台），
  // 注入它时应返回 null 且不读文件 —— 即使文件不存在也不报错。
  const result = verifyCoreBinary('/definitely/not/here', 'freebsd', 'x64');
  assert.equal(result, null);
});

test('verifyCoreBinary：linux 现在也在校验范围内', async () => {
  // 修复前 linux 无 pin（盲区）；修复后 linux-x64/arm64 都有 pin，
  // 所以对不匹配的内容应返回错误，而不是跳过。
  const dir = await mkdtemp(path.join(tmpdir(), 'mihomo-test-'));
  const fake = path.join(dir, 'fake-linux-core');
  try {
    await writeFile(fake, Buffer.from('not the real linux core'));
    const result = verifyCoreBinary(fake, 'linux', 'x64');
    assert.notEqual(result, null);
    assert.match(result, /linux-x64/);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('verifyCoreBinary：读失败 fail-closed（不静默放行）', () => {
  // 传一个目录冒充文件：existsSync 为真但 readFileSync 抛 EISDIR。
  // 安全校验不能因此放行，必须返回错误。
  const result = verifyCoreBinary('C:/deepseek插件/_audit-final/fixwork/lib', 'win32', 'x64');
  assert.notEqual(result, null);
  assert.match(result, /读取失败/);
});

test('verifyCoreBinary：有 pin 平台且字节不匹配时返回带平台/路径/双 hash 的错误', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'mihomo-test-'));
  const fake = path.join(dir, 'mihomo.exe');
  try {
    await writeFile(fake, Buffer.from('this is definitely not the real core'));
    const result = verifyCoreBinary(fake, 'win32', 'x64');
    assert.notEqual(result, null);
    assert.match(result, /SHA256 不匹配/);
    assert.match(result, /win32-x64/);
    assert.match(result, /mihomo\.exe/);
    assert.match(result, /期望：/);
    assert.match(result, /实际：/);
    assert.match(result, /DSH_TUNNEL_CORE_PATH/);
    assert.match(result, /提交 PR/);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('verifyCoreBinary：错误信息里的实际 hash 与文件真实 sha256 前 12 位一致', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'mihomo-test-'));
  const fake = path.join(dir, 'mihomo.exe');
  try {
    const content = Buffer.from('malicious payload for hash check');
    await writeFile(fake, content);
    const realSha = createHash('sha256').update(content).digest('hex').slice(0, 12);
    const result = verifyCoreBinary(fake, 'win32', 'x64');
    assert.notEqual(result, null);
    assert.match(result, new RegExp(realSha));
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});

test('verifyCoreBinary：linux 下载缓存与 npm 包用不同的 pin 表', async () => {
  // Linux 两条来源的二进制不同：coreAssetName() 下载的是 compatible 变体，
  // npm 平台包是普通变体。若用同一张表，正常内核会被误拒。
  const dir = await mkdtemp(path.join(tmpdir(), 'mihomo-test-'));
  const fake = path.join(dir, 'fake-core');
  try {
    await writeFile(fake, Buffer.from('x'));
    const asNpm = verifyCoreBinary(fake, 'linux', 'x64', 'npm');
    const asDownloaded = verifyCoreBinary(fake, 'linux', 'x64', 'downloaded');
    // 两者都应判失败（内容不对），但期望值必须不同 —— 证明用了不同的表。
    assert.notEqual(asNpm, null);
    assert.notEqual(asDownloaded, null);
    const npmExpected = (asNpm.match(/期望：(.{12})/) || [])[1];
    const dlExpected = (asDownloaded.match(/期望：(.{12})/) || [])[1];
    assert.notEqual(npmExpected, dlExpected, 'linux npm 与下载缓存应使用不同 pin');
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
});
