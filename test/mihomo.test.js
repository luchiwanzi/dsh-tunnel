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
import { verifyCoreBinary, coreSource, expectedSha256, digestMatches, CORE_VERSION } from '../lib/mihomo.js';

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

test('verifyCoreBinary：读失败 fail-closed（不静默放行）', async () => {
  // 用 mkdtemp 现造一个目录冒充内核文件：existsSync 为真但 readFileSync 抛
  // EISDIR。这样在任何机器（含 CI）上都真的走 EISDIR 分支 —— 之前用硬编码的
  // 绝对路径，在 CI 上只会因为「路径不存在」而恰好通过，从没测到目标分支。
  const dir = await mkdtemp(path.join(tmpdir(), 'mihomo-eisdir-'));
  try {
    const result = verifyCoreBinary(dir, 'win32', 'x64');
    assert.notEqual(result, null);
    assert.match(result, /读取失败/);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
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

test('coreSource：npm 包路径判定为 npm，其余为 downloaded', () => {
  // 这是「用错表就会误拒正常内核」的关键分支，之前没有测试兜着。
  assert.equal(coreSource('/a/b/mihomo.exe', '/a/b/mihomo.exe'), 'npm');
  // 大小写/分隔符差异也应判定为同一文件（path.resolve 归一化）。
  assert.equal(coreSource('/a/b/mihomo.exe', null), 'downloaded');
  assert.equal(coreSource('/a/b/mihomo.exe', '/a/c/mihomo.exe'), 'downloaded');
  assert.equal(coreSource('/a/b/mihomo.exe', undefined), 'downloaded');
});

test('expectedSha256：linux 两种来源命中不同的表', () => {
  const npm = expectedSha256('linux', 'x64', 'npm');
  const dl = expectedSha256('linux', 'x64', 'downloaded');
  assert.equal(npm.table, 'PACKAGED_CORE_SHA256');
  assert.equal(dl.table, 'DOWNLOADED_CORE_SHA256');
  assert.notEqual(npm.digest, dl.digest, 'linux npm 与下载缓存应不同 pin');
});

test('expectedSha256：非 Linux 的 downloaded 回落到 npm 表', () => {
  // Windows/macOS 没有 DOWNLOADED 条目，必须回落到 PACKAGED，
  // 否则它们的缓存内核完全不校验（之前的 fail-open 漏洞）。
  const win = expectedSha256('win32', 'x64', 'downloaded');
  assert.notEqual(win, null);
  assert.equal(win.table, 'PACKAGED_CORE_SHA256');
  const mac = expectedSha256('darwin', 'arm64', 'downloaded');
  assert.equal(mac.table, 'PACKAGED_CORE_SHA256');
});

test('expectedSha256：两张表都没有的平台返回 null（不校验）', () => {
  assert.equal(expectedSha256('freebsd', 'x64', 'downloaded'), null);
  assert.equal(expectedSha256('freebsd', 'x64', 'npm'), null);
});

test('digestMatches：成功路径的判定逻辑', () => {
  // 成功路径用纯函数验证 —— 真实内核是 60MB 二进制，测试里既造不出 hash
  // 恰好等于 pin 的文件，也不该依赖任何本机路径。
  const pin = expectedSha256('win32', 'x64', 'npm').digest;
  assert.equal(digestMatches(pin, pin), true, '实际值与 pin 一致应通过');
  assert.equal(digestMatches('deadbeef', pin), false, '不一致应拒绝');
  assert.equal(digestMatches(undefined, pin), false);
  assert.equal(digestMatches(null, pin), false);
});

test('expectedSha256 的 pin 都是 64 位小写 hex', () => {
  // 防止手抄 pin 时漏字符或混入大写，那会让校验永远失败。
  const platforms = [
    ['win32', 'x64'], ['win32', 'arm64'],
    ['darwin', 'x64'], ['darwin', 'arm64'],
    ['android', 'arm64'],
    ['linux', 'x64'], ['linux', 'arm64'],
  ];
  for (const [p, a] of platforms) {
    for (const src of ['npm', 'downloaded']) {
      const entry = expectedSha256(p, a, src);
      if (entry === null) continue;
      assert.match(entry.digest, /^[0-9a-f]{64}$/, `${p}-${a}/${src} 的 pin 格式不对`);
    }
  }
});
