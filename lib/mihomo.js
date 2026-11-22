/**
 * mihomo (Clash.Meta) process lifecycle: binary provisioning, config
 * generation, readiness checks, and the local Clash API.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { chmod, copyFile, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createServer, isIP } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { createHash, randomBytes } from 'node:crypto';
import { stringify as stringifyYaml } from 'yaml';

export const CORE_VERSION = 'v1.19.33';
const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** 旧版本把运行数据放在包目录下，升级后需要从这里搬走。 */
export const LEGACY_DATA_DIR = path.join(PLUGIN_ROOT, '.data');
/**
 * 运行数据放在用户目录，不放在包目录：包目录在升级时会被整体替换，
 * 放在里面等于每次升级都丢掉订阅和节点凭据。Windows 没有 Unix 权限位，
 * 用户目录默认 ACL 就是「仅本人」，比在包目录里 chmod 更可靠。
 * 部署方可用 DSH_TUNNEL_DATA_DIR 覆盖到自定义位置。
 */
export const DATA_DIR = process.env.DSH_TUNNEL_DATA_DIR
  ?? path.join(os.homedir(), '.dsh', 'tunnel');
export const CONFIG_PATH = path.join(DATA_DIR, 'config.yaml');
export const CORE_PATH = path.join(DATA_DIR, 'mihomo');

const MAX_ARCHIVE_BYTES = 80 * 1024 * 1024;
const CORE_DOWNLOAD_ROOT = `https://github.com/MetaCubeX/mihomo/releases/download/${CORE_VERSION}`;

// 各平台内核压缩包的官方 SHA256（来自 GitHub release 资产的 digest 字段）。
// 下载后必须逐字节比对，防止供应链投毒。
const CORE_SHA256 = {
  'linux-x64': '386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6',
  'linux-arm64': 'ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187',
};

/**
 * npm 平台包（@pkgship/mihomo-<os>-<arch>）里二进制的 SHA256。
 *
 * 与 CORE_SHA256 的区别：CORE_SHA256 钉的是「Linux 回退下载路径」里 GitHub
 * release 压缩包的 digest；这张表钉的是「Windows / macOS / Android 直接走
 * npm 包」时，包里那个已解压二进制的字节。二者都是内容级校验，只是数据源
 * 不同 —— 前者 pin 压缩包，后者 pin 裸二进制。
 *
 * 值来源：下载各平台 @pkgship/mihomo-*@1.19.33 tarball，解压出 bin/ 下的
 * 二进制后逐字节算 sha256，再与官方 GitHub release v1.19.33 对应 asset
 * 解压出的二进制比对一致后填入。
 *
 * 对应官方 asset（逐字节核对一致）：
 *   win32-x64      -> mihomo-windows-amd64-v1.19.33.zip
 *   win32-arm64    -> mihomo-windows-arm64-v1.19.33.zip
 *   darwin-x64     -> mihomo-darwin-amd64-v1.19.33.gz
 *   darwin-arm64   -> mihomo-darwin-arm64-v1.19.33.gz
 *   android-arm64  -> mihomo-android-arm64-v8-v1.19.33.gz
 *   linux-x64      -> mihomo-linux-amd64-compatible-v1.19.33.gz（见下）
 *   linux-arm64    -> mihomo-linux-arm64-v1.19.33.gz
 *
 * 为什么包含 linux：Linux 有两条内核来源 —— CORE_PATH 缓存（由 CORE_SHA256
 * 校验 .gz 后解压写入）和 npm 平台包（@pkgship/mihomo-linux-* 已作为可选依赖
 * 安装）。后者在 CORE_PATH 不存在时会被 packagedCorePath() 命中，是一条真实
 * 路径，若不 pin 就成了校验盲区。
 *
 * 注意 linux-x64 的两份二进制并不相同：npm 平台包里是**普通 amd64 变体**，
 * 而 coreAssetName() 下载的是 **compatible 变体**。所以下面这张 npm 表里
 * linux-x64 填的是普通 amd64 的 hash，下载缓存的那份在 DOWNLOADED_CORE_SHA256。
 */
const PACKAGED_CORE_SHA256 = {
  'win32-x64': '1cde41cfffd3de0aedad63c0a8515e1ce5eea507e8133aed0f637d316c93800a',
  'win32-arm64': '6f6e471b2fea55c54c0d98fc4b559fb06627456ed50febaf7a5572508b225529',
  'darwin-x64': 'f036d657e73f53d3c9171fddf9cf4f559acca9391311292f01d2c7564c299d58',
  'darwin-arm64': 'f3e8ae41397c08cbf900ce1f7c8a168285d29954e9bca5d84d69a2b2561adfe9',
  'android-arm64': 'cfa0be78846bfef7272fe5a73089f8cf0e1f15a6ffb601f5cc809f457f712f67',
  'linux-x64': '09c2cb429cf45fb56884ceb91a0e5b17cc8b2c866c07811bcf75dfb59fef7662',
  'linux-arm64': '8c73570d9a5f388bc2f58eee0b347ccfab84fb3cf1a0f8f2cf5eac7005fbcdc0',
};

/**
 * Linux 下载缓存内核（CORE_PATH）的 SHA256 —— 即 `mihomo -t` 用的那个裸二进制。
 *
 * 为什么需要单独一张表：Linux 的内核有两条来源，二进制并不总是相同。
 * `coreAssetName()` 下载的是 `mihomo-linux-amd64-compatible-*`（compatible 变体），
 * 而 npm 平台包里的 `linux-x64` 是普通 amd64 变体 —— 两者字节不同。
 * 若用同一张表按平台查，会拿 npm 的 pin 去校验下载缓存，导致正常内核被误拒。
 *
 * 实测（v1.19.33）：
 *   linux-x64  下载缓存 817f50b3…  ≠ npm 09c2cb42…
 *   linux-arm64 下载缓存 8c73570d… = npm 8c73570d…（相同，仍列出以免将来分叉时遗漏）
 */
const DOWNLOADED_CORE_SHA256 = {
  'linux-x64': '817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f',
  'linux-arm64': '8c73570d9a5f388bc2f58eee0b347ccfab84fb3cf1a0f8f2cf5eac7005fbcdc0',
};

const PACKAGED_CORES = {
  'linux-x64': '@pkgship/mihomo-linux-amd64',
  'linux-arm64': '@pkgship/mihomo-linux-arm64',
  'darwin-x64': '@pkgship/mihomo-darwin-amd64',
  'darwin-arm64': '@pkgship/mihomo-darwin-arm64',
  'win32-x64': '@pkgship/mihomo-windows-amd64',
  'win32-arm64': '@pkgship/mihomo-windows-arm64',
  'android-arm64': '@pkgship/mihomo-android-arm64',
};

/** Path of the platform binary installed from the npm package, if present. */
function packagedCorePath() {
  const packageName = PACKAGED_CORES[`${process.platform}-${process.arch}`];
  if (packageName === undefined) return null;
  try {
    const requireFromPlugin = createRequire(import.meta.url);
    // The platform binary is an optional dependency of the meta package, so it
    // lives below that package instead of being hoisted to the plugin root.
    const metaManifest = requireFromPlugin.resolve('@pkgship/mihomo/package.json');
    const candidate = createRequire(metaManifest)(packageName);
    if (typeof candidate === 'string' && existsSync(candidate)) return candidate;
  } catch {
    // Optional platform package not installed; fall back to a download.
  }
  return null;
}

/**
 * 某平台「该用哪个 pin 校验、是否有 pin」的唯一判定点。
 *
 * 判断与取值放在同一处，避免「判断有没有 pin」和「取哪个 hash 比对」两处
 * 逻辑漂移。返回 null 表示该平台不校验（Linux 走下载 .gz 校验、未知架构无 pin）。
 */
/**
 * 判定一个内核文件的「来源」，决定用哪张 pin 表校验。
 *
 * 抽成纯函数是为了可测：`ensureCore` 里依赖文件系统与 npm 解析，很难在
 * 单测里构造，而来源判定恰恰是"用错表就会误拒正常内核"的关键分支。
 *
 * @param {string} target 实际要用的内核路径
 * @param {string | null} packaged npm 平台包解析出的路径（未安装时为 null）
 * @returns {'npm' | 'downloaded'}
 */
export function coreSource(target, packaged) {
  if (packaged === null || packaged === undefined) return 'downloaded';
  return path.resolve(packaged) === path.resolve(target) ? 'npm' : 'downloaded';
}

/**
 * 某平台 + 某来源对应的 pin 值与表名；两张表都没有时返回 null。
 * 导出供测试直接断言"用哪张表"，避免靠错误文案间接推断。
 */
export function expectedSha256(platform, arch, source) {
  const key = `${platform}-${arch}`;
  // 按「文件来源」选表：npm 平台包与 Linux 下载缓存是两份不同的二进制。
  // 返回命中的表名，好让错误文案指向用户真正该改的那张表。
  if (source === 'downloaded') {
    const downloaded = DOWNLOADED_CORE_SHA256[key];
    if (typeof downloaded === 'string') return { digest: downloaded, table: 'DOWNLOADED_CORE_SHA256' };
    // 回落：非 Linux 平台不存在「下载缓存」表项，但它们的 CORE_PATH 里那份
    // 二进制只可能是 npm 包二进制的副本（插件从不主动往那里写别的），
    // 所以用 npm 表校验语义正确。若不回落，Windows/macOS 的缓存内核会
    // 完全不被校验 —— 与 README「所有平台都校验」的声明矛盾。
    const fallback = PACKAGED_CORE_SHA256[key];
    if (typeof fallback === 'string') return { digest: fallback, table: 'PACKAGED_CORE_SHA256' };
    // 两张表都没有：插件不支持的平台，维持既定语义（不校验）。
    return null;
  }
  const packaged = PACKAGED_CORE_SHA256[key];
  return typeof packaged === 'string' ? { digest: packaged, table: 'PACKAGED_CORE_SHA256' } : null;
}

/**
 * 校验内核二进制是否与钉住的值一致。
 *
 * 与 ensureCore 里对 Linux 下载压缩包的校验不同：这里二进制在 `pnpm install`
 * 时就已经落到 node_modules，插件只是「找到并使用它」。所以校验点是启动前，
 * 而不是下载时 —— 一旦字节对不上，说明 npm 包内容被改动（投毒或上游重发布），
 * 必须拒绝启动，而不是静默使用一个来路不明的内核。
 *
 * 刻意不使用 digestOf() 的 size:mtime 缓存：安全校验要每次冷读，缓存会留下
 * 「同 size 同 mtime 被替换」的绕过窗口，得不偿失。60MB 冷读约 100ms，连接
 * 场景可接受。
 *
 * @param {string} binaryPath 二进制绝对路径
 * @param {string} [platform] 默认当前平台，测试可注入
 * @param {string} [arch] 默认当前架构，测试可注入
 * @returns {string | null} 校验失败时返回给用户的错误信息；通过或无需校验则返回 null
 */
export function verifyCoreBinary(binaryPath, platform = process.platform, arch = process.arch, source = 'npm') {
  const expected = expectedSha256(platform, arch, source);
  // 两张表都没有该平台：插件不支持它，维持既定语义（不校验、不读文件）。
  if (expected === null) return null;
  let actual;
  try {
    actual = createHash('sha256').update(readFileSync(binaryPath)).digest('hex');
  } catch (error) {
    // 调用方已经确认文件存在，读失败只可能是权限 / 被占用 / IO 错误。
    // 安全校验不能在这种情况下静默放行 —— fail-open 等于给出一条绕过路径。
    return [
      'mihomo 内核完整性校验无法完成（读取失败），已拒绝启动以保护安全。',
      `平台：${platform}-${arch}`,
      `内核路径：${binaryPath}`,
      `原因：${errorMessage(error)}`,
      '立即解决：确认该文件可读；或设置 DSH_TUNNEL_CORE_PATH 指向一个你自己校验过的 mihomo 可执行文件。',
    ].join('\n');
  }
  if (actual === expected.digest) return null;
  const lines = [
    'mihomo 内核完整性校验失败（SHA256 不匹配），已拒绝启动以保护安全。',
    `平台：${platform}-${arch}`,
    `内核路径：${binaryPath}`,
    `期望：${expected.digest.slice(0, 12)}…`,
    `实际：${actual.slice(0, 12)}…`,
    `来源：${source === 'downloaded' ? '下载缓存' : 'npm 平台包'}`,
    '可能原因：内核被篡改，或上游重新发布了同版本号的包。',
  ];
  // 缓存内核是插件自己下载/迁移来的，用户手里有它的删除权；把它删掉就能
  // 让插件重新下载一份正确的。npm 包路径不能这么建议 —— 那是依赖树的一部分。
  if (source === 'downloaded') {
    lines.push(`缓存内核自愈：删除 ${binaryPath} 后重新点击连接，插件会重新下载并校验正确版本。`);
  }
  lines.push('或设置 DSH_TUNNEL_CORE_PATH 指向一个你自己校验过的 mihomo 可执行文件。');
  lines.push(`长期解决：若确认为上游合法更新，请向本仓库提交 PR 更新 ${expected.table}。`);
  return lines.join('\n');
}

/** Resolve the core path, honoring a caller override. */
export function resolveCorePath(customPath) {
  if (typeof customPath === 'string' && customPath.trim() !== '') return customPath.trim();
  if (existsSync(CORE_PATH)) return CORE_PATH;
  return packagedCorePath() ?? CORE_PATH;
}

/** Return an installed core, downloading the Linux release as a fallback. */
export async function ensureCore(customPath, onDownloading) {
  // 用户通过 DSH_TUNNEL_CORE_PATH 指定的内核：跳过 pin 校验，用户自己对这份
  // 二进制负责。必须在这里提前返回 —— 校验逻辑不能只靠「平台有无 pin」来
  // 猜是不是用户自定义路径，那样会误伤用户自编译的内核。
  if (typeof customPath === 'string' && customPath.trim() !== '') {
    const custom = customPath.trim();
    // 路径必须真实存在：直接返回一个不存在的路径，会在后面 spawn 时退化成一个
    // 与「内核缺失」无关的模糊错误，用户看不出是路径写错了。
    if (!existsSync(custom)) {
      throw new Error(`指定的 mihomo 内核不存在：${custom}。请检查 DSH_TUNNEL_CORE_PATH 或插件配置中的 corePath`);
    }
    return custom;
  }

  const target = resolveCorePath(customPath);
  if (existsSync(target)) {
    // 启动前做一次字节级 pin 校验。放在这里而不是 resolveCorePath 里：
    // resolveCorePath 被 publicState() 每 700ms 轮询调用一次，在那里校验会
    // 反复读 60MB 二进制算 hash，拖垮事件循环。
    //
    // 校验要按「文件来源」选 pin：npm 平台包里的二进制与 Linux 下载缓存
    // （compatible 变体解压）可能不是同一份字节，用错表会把正常内核误拒。
    const source = coreSource(target, packagedCorePath());
    const failure = verifyCoreBinary(target, process.platform, process.arch, source);
    if (failure !== null) throw new Error(failure);
    return target;
  }

  const asset = coreAssetName();
  if (asset === null) {
    throw new Error(`暂不支持自动安装 ${process.platform}/${process.arch} 的 mihomo 内核；请设置 DSH_TUNNEL_CORE_PATH 指向已有的 mihomo 可执行文件`);
  }
  onDownloading?.();

  const url = `${CORE_DOWNLOAD_ROOT}/${asset}`;
  let response;
  try {
    response = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': `dsh-tunnel/1.0 (${CORE_VERSION})`, accept: 'application/octet-stream' },
      signal: AbortSignal.timeout(180_000),
    });
  } catch (error) {
    throw new Error(`下载 mihomo 内核失败：${errorMessage(error)}（${url}）`);
  }
  if (!response.ok) {
    throw new Error(`下载 mihomo 内核失败：HTTP ${response.status}（${url}）`);
  }

  const compressed = Buffer.from(await response.arrayBuffer());
  if (compressed.byteLength === 0 || compressed.byteLength > MAX_ARCHIVE_BYTES) {
    throw new Error(`mihomo 内核压缩包大小异常（${compressed.byteLength} 字节）`);
  }

  const expectedSha = CORE_SHA256[`${process.platform}-${process.arch}`];
  if (typeof expectedSha === 'string') {
    const actualSha = createHash('sha256').update(compressed).digest('hex');
    if (actualSha !== expectedSha) {
      throw new Error(`mihomo 内核压缩包校验失败（SHA256 不匹配），已中止下载以保护安全`);
    }
  }

  let binary;
  try {
    binary = gunzipSync(compressed);
  } catch (error) {
    throw new Error(`mihomo 内核解压失败：${errorMessage(error)}`);
  }
  if (binary.byteLength < 1_000_000 || !(binary[0] === 0x7f && binary[1] === 0x45 && binary[2] === 0x4c && binary[3] === 0x46)) {
    throw new Error('下载的 mihomo 内核不是有效的 Linux 可执行文件');
  }

  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.download`;
  try {
    await writeFile(temporary, binary, { mode: 0o755 });
    await chmod(temporary, 0o755);
    await rename(temporary, target);
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
  return target;
}

function coreAssetName() {
  if (process.platform !== 'linux') return null;
  if (process.arch === 'x64') return `mihomo-linux-amd64-compatible-${CORE_VERSION}.gz`;
  if (process.arch === 'arm64') return `mihomo-linux-arm64-${CORE_VERSION}.gz`;
  return null;
}

/** Pick two distinct free loopback ports. */
export async function allocatePorts() {
  const first = await freePort();
  let second = await freePort();
  let attempts = 0;
  while (second === first && attempts++ < 8) second = await freePort();
  return { mixedPort: first, apiPort: second };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      server.close((error) => {
        if (error) reject(error);
        else if (port > 0) resolve(port);
        else reject(new Error('无法分配本地端口'));
      });
    });
  });
}

/**
 * Rules that keep mainland-China traffic off the tunnel.
 *
 * The harness is used from mainland China, and the tunnel exists to reach
 * services that are slow or unreachable from there. Every domestic request
 * routed through it is wasted twice: it pays the subscription's traffic, and
 * it detours through a foreign hop to reach a server that is nearer than the
 * exit node. Domestic-first matching turns that around — GEOSITE,cn and
 * GEOIP,CN resolve to DIRECT before MATCH sends everything else to the node.
 *
 * Ordering matters: these must sit after the loopback/private guards and
 * before MATCH, or the catch-all would claim the traffic first.
 */
const CN_DIRECT_RULES = [
  'GEOSITE,cn,DIRECT',
  'GEOIP,CN,DIRECT',
  'GEOSITE,private,DIRECT',
  'GEOIP,private,DIRECT',
];

/**
 * Turn a user's extra "go direct" entries into mihomo rules.
 *
 * GEOSITE,cn misses services that are domestic in practice but absent from the
 * list — a small CDN, a company portal, an intranet name. Rather than asking
 * for a rule language, the config takes bare tokens and picks the rule type
 * from the shape of each one:
 *
 *   example.com     -> DOMAIN-SUFFIX,example.com,DIRECT
 *   .corp.internal  -> DOMAIN-SUFFIX,corp.internal,DIRECT   (leading dot is noise)
 *   10.20.30.0/24   -> IP-CIDR,10.20.30.0/24,DIRECT,no-resolve
 *   192.168.1.5     -> IP-CIDR,192.168.1.5/32,DIRECT,no-resolve
 *
 * Entries that are neither a hostname nor an address are dropped instead of
 * being passed through: a malformed rule makes the core refuse the whole
 * config, which would turn one typo into "the tunnel will not start".
 */
function userDirectRules(extra) {
  if (!Array.isArray(extra)) return [];
  const rules = [];
  const seen = new Set();
  for (const raw of extra) {
    const value = typeof raw === 'string' ? raw.trim().replace(/^\./, '') : '';
    if (value === '' || seen.has(value)) continue;
    seen.add(value);
    if (value.includes('/')) {
      const [base, prefix] = value.split('/');
      const version = isIP(base);
      const bits = Number(prefix);
      // A prefix that is not an integer, or is outside the family's range,
      // produces a rule the core refuses — and it refuses the whole config, not
      // just the line. `1.2.3.4/abc` and `2001:db8::1/200` both arrived here
      // during testing and both had to be rejected before reaching mihomo.
      if (!/^\d{1,3}$/.test(prefix)) continue;
      // /0 会把整族流量钉成直连，隧道等于没开，而界面照样显示"已连接"。
      if (bits === 0) continue;
      if (version === 4 && bits <= 32) {
        rules.push(`IP-CIDR,${base}/${bits},DIRECT,no-resolve`);
      } else if (version === 6 && bits <= 128) {
        rules.push(`IP-CIDR,${base}/${bits},DIRECT,no-resolve`);
      }
      continue;
    }
    if (isIP(value) === 4) {
      rules.push(`IP-CIDR,${value}/32,DIRECT,no-resolve`);
      continue;
    }
    if (isIP(value) === 6) {
      rules.push(`IP-CIDR,${value}/128,DIRECT,no-resolve`);
      continue;
    }
    // A hostname. The IPv4-looking check runs first above, so "999.1.1.1" — not
    // a legal address — is refused here rather than becoming a suffix rule that
    // silently never matches.
    if (/^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(value) && !/^[\d.]+$/.test(value)) {
      rules.push(`DOMAIN-SUFFIX,${value},DIRECT`);
    }
  }
  return rules;
}

/** Generate a complete mihomo configuration for the supplied nodes. */
export function buildConfig(nodes, options) {
  const { mixedPort, apiPort, secret, hosts = {}, cnDirect = true, directHosts = [] } = options;
  let group = 'DSH-TUNNEL';
  const names = new Set(nodes.map((node) => node.name));
  while (names.has(group)) group += '_';
  const hostOverrides = hosts !== null && typeof hosts === 'object' && Object.keys(hosts).length > 0 ? { hosts } : {};

  const config = {
    'mixed-port': mixedPort,
    'allow-lan': false,
    'bind-address': '127.0.0.1',
    mode: 'rule',
    'log-level': 'warning',
    ipv6: false,
    'external-controller': `127.0.0.1:${apiPort}`,
    secret,
    'unified-delay': true,
    'tcp-concurrent': true,
    profile: { 'store-selected': false, 'store-fake-ip': false },
    // Resolve GEOSITE/GEOIP from the bundled database files rather than a
    // remote rule-provider fetch: the tunnel may be the only working route at
    // connect time, so a rule set that has to be downloaded first cannot be
    // relied on.
    'geodata-mode': true,
    ...hostOverrides,
    proxies: nodes.map((node) => ({ ...node })),
    'proxy-groups': [{ name: group, type: 'select', proxies: nodes.map((node) => node.name) }],
    rules: [
      'DOMAIN-SUFFIX,localhost,DIRECT',
      'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
      'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
      'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
      'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
      'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve',
      'IP-CIDR6,::1/128,DIRECT,no-resolve',
      'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
      // Domestic traffic goes direct; only what is left reaches the node.
      ...(cnDirect ? CN_DIRECT_RULES : []),
      // User extras last, so a site the databases classify as foreign can still
      // be pinned to DIRECT without editing the rule set itself.
      ...userDirectRules(directHosts),
      `MATCH,${group}`,
    ],
  };
  return { text: stringifyYaml(config, { lineWidth: 0 }), group };
}


// ---------------------------------------------------------------------------
// Geodata provisioning for the China-direct rule set
// ---------------------------------------------------------------------------
//
// `GEOSITE,cn` and `GEOIP,CN` need mihomo's rule databases next to the core:
// GeoSite.dat and GeoIP.dat in DATA_DIR. The core downloads them by itself on
// first start, but that download is the one thing this plugin cannot fall back
// on — a user reaching for the tunnel is by definition on a network where the
// official sources may be exactly what is unreachable, and a half-finished
// download leaves the core waiting indefinitely (measured: GeoSite.dat fetched,
// GeoIP.dat left at 0 bytes, startup never completed).
//
// So the databases are provisioned here instead, before the core starts:
// mirrors in the order that works from mainland China, an exact size floor per
// file, and a hard cap on the wait. When every source fails the caller turns
// the China-direct rules off and connects as before — degraded, still working.

const GEODATA_MIN_BYTES = 1_000_000;
/**
 * How long one source may go without progress before it is abandoned.
 *
 * This is a STALL budget, not a total budget, and the distinction is the whole
 * reason this constant is not a plain AbortSignal.timeout(): measured here, the
 * response headers for a 2.9 MB database arrive in about one second and the body
 * then takes considerably longer. A total-duration timeout fired while the body
 * was still streaming in, which read as "every mirror is down" when in fact the
 * download was making progress the whole time. The timer is therefore reset on
 * every chunk, so a slow-but-moving transfer is allowed to finish and a dead one
 * is caught quickly.
 */
const GEODATA_STALL_MS = 20_000;
/**
 * Budget for the whole provisioning step, both files and every mirror.
 *
 * A hard ceiling on the wait matters more than a complete download: the user
 * pressed Connect, and the branch that follows a timeout still connects. A dead
 * network then costs three minutes instead of the twelve a serial walk of every
 * mirror at a generous timeout would take (2 files x 3 sources x 120s).
 *
 * 180 seconds = 3 minutes, and the two databases download in parallel, so in
 * the worst case each file gets the full budget rather than a half of it.
 */
const GEODATA_BUDGET_MS = 180_000;

/**
 * The commit the databases are pinned to.
 *
 * Every mirror below is addressed by this commit rather than by a branch or a
 * rolling release tag, because the SHA-256 pins and a moving target cannot
 * coexist: Loyalsoldier republishes `release` regularly, and the moment it
 * does, a digest recorded against the old bytes starts rejecting the new file.
 * Measured while writing this: the same URL served `118d2e13…` one week and
 * `268f3061…` the next. With a rolling tag the failure is silent — every mirror
 * mismatches, provisioning reports the databases as missing, and the plugin
 * quietly connects with split routing off while the user believes it is on.
 *
 * Pinning a commit makes the bytes a fixed fact, so the digests below stay
 * true. Bumping the pin is a deliberate commit that updates both this constant
 * and GEODATA_SHA256 together.
 */
const GEODATA_COMMIT = '3914c5cf42be87696db5139fc4b7d681b09b8d4a';

/**
 * Sources per database, best first. All three serve the SAME bytes: the first
 * two are jsDelivr edges of the pinned commit, the third is the same commit's
 * file from GitHub itself. They are mirrors, not alternatives — a source that
 * returns a different file is a source that failed the digest check below.
 */
const GEODATA_SOURCES = {
  'GeoSite.dat': [
    `https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@${GEODATA_COMMIT}/geosite.dat`,
    `https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@${GEODATA_COMMIT}/geosite.dat`,
    `https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/${GEODATA_COMMIT}/geosite.dat`,
  ],
  'GeoIP.dat': [
    `https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@${GEODATA_COMMIT}/geoip.dat`,
    `https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@${GEODATA_COMMIT}/geoip.dat`,
    `https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/${GEODATA_COMMIT}/geoip.dat`,
  ],
};

/**
 * SHA-256 of the file at GEODATA_COMMIT, per database.
 *
 * Because every source is addressed by the same commit, one digest per database
 * is exact rather than approximate: a mismatch means the bytes are not that
 * commit's bytes, and the download is rejected instead of promoted. Regenerate
 * both this table and GEODATA_COMMIT in the same change when bumping the pin.
 */
const GEODATA_SHA256 = {
  'GeoSite.dat': '268f30619cfe5db5a925766bf966045f23b58b9a57bbc00c00396eb548011814',
  'GeoIP.dat': '304ac8a1cbcc8166e4f5a4f32955e4d0fb77a1bd713583e371b30ee27f3659d8',
};

/**
 * Where the rule databases live.
 *
 * `DSH_TUNNEL_GEODATA_DIR` takes precedence when set: a deployment that cannot
 * reach the mirrors — an intranet, an air-gapped host, or a network where the
 * download simply keeps failing — drops the two files in that directory and the
 * plugin uses them as-is, with no download and no digest check. The digest
 * exists to vouch for what the plugin fetched itself; a file the operator
 * supplied is their responsibility, and refusing it would defeat the point of
 * the escape hatch.
 */
function geodataDir() {
  const override = process.env.DSH_TUNNEL_GEODATA_DIR;
  if (typeof override === 'string' && override.trim() !== '') return override.trim();
  return DATA_DIR;
}

/** True when an operator has taken over database provisioning. */
export function geodataIsExternal() {
  const override = process.env.DSH_TUNNEL_GEODATA_DIR;
  return typeof override === 'string' && override.trim() !== '';
}

function geodataPath(name) {
  return path.join(geodataDir(), name);
}

/**
 * Cached SHA-256 of a file, or null when it cannot be read.
 *
 * Hashing 27 MB takes ~21 ms, and `geodataStatus` runs on every state read —
 * including the 700 ms poll the settings page does while a connect is in
 * progress. Re-reading both databases on each poll would stall the event loop
 * for ~42 ms at a time, during the exact window where the UI is waiting.
 * Size and mtime identify the bytes well enough here: both change whenever the
 * file is rewritten, and a same-size/same-mtime substitution on this host is
 * already inside the threat model of a local attacker.
 */
const digestCache = new Map();

function digestOf(filePath) {
  let stat;
  try {
    stat = statSync(filePath);
  } catch {
    return null;
  }
  const key = `${stat.size}:${stat.mtimeMs}`;
  const cached = digestCache.get(filePath);
  if (cached !== undefined && cached.key === key) return cached.digest;
  let digest;
  try {
    digest = createHash('sha256').update(readFileSync(filePath)).digest('hex');
  } catch {
    return null;
  }
  digestCache.set(filePath, { key, digest });
  return digest;
}

/**
 * Whether the database `name` inside `dir` is trustworthy enough to use.
 *
 * Inside `DATA_DIR` the plugin is the one that fetched the file, so the pinned
 * digest must match: a size floor alone accepts a truncated download, and a
 * fetch aborted mid-stream leaves exactly that — a couple of megabytes in a
 * file that looks large enough. The next connect then hands the core a database
 * it rejects, the core starts downloading on its own, and the failure repeats
 * every time. Comparing the digest turns that wedge into "fetch it again".
 *
 * An operator-supplied directory has no pinned digest to compare against — the
 * whole point of `DSH_TUNNEL_GEODATA_DIR` is to let a deployment track its own
 * copy, possibly a newer one — so only the size floor applies there.
 */
export function geodataVerified(name, dir, options = {}) {
  const filePath = path.join(dir, name);
  try {
    if (statSync(filePath).size < GEODATA_MIN_BYTES) return false;
  } catch {
    return false;
  }
  // `trusted` marks a copy the operator supplied. The pinned digest exists to
  // vouch for what this plugin fetched itself; a file the operator staged may
  // deliberately be newer than the pin, and refusing it would defeat the point
  // of the escape hatch.
  if (options.trusted === true) return true;
  const expected = GEODATA_SHA256[name];
  if (typeof expected !== 'string') return true;
  return digestOf(filePath) === expected;
}

/** A database the core can actually read, in the directory it reads from. */
function geodataReady(name) {
  return geodataVerified(name, geodataDir(), { trusted: geodataIsExternal() });
}

/**
 * Fetch one source into place; returns false instead of throwing.
 *
 * `deadline` is the epoch millisecond after which the caller stops caring, so
 * the per-request timeout is the smaller of the per-file timeout and whatever
 * budget is left. Without that, three dead mirrors each burn the full per-file
 * timeout and the sum overshoots the budget the caller was promised.
 */
async function downloadGeodata(name, url, deadline, signal, log) {
  const target = geodataPath(name);
  const temporary = `${target}.download`;
  const controller = new AbortController();
  let stallTimer = null;
  const armStallTimer = () => {
    if (stallTimer !== null) clearTimeout(stallTimer);
    stallTimer = setTimeout(() => controller.abort(), GEODATA_STALL_MS);
  };
  // An external cancel (the user pressed Disconnect) must abort the fetch the
  // same as a stall: without this the download keeps going after the caller has
  // already moved on.
  const onAbort = () => controller.abort();
  if (signal !== undefined && signal !== null) {
    if (signal.aborted) return false;
    signal.addEventListener('abort', onAbort, { once: true });
  }
  try {
    await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
    await chmod(DATA_DIR, 0o700).catch(() => {});

    armStallTimer();
    const response = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': `dsh-tunnel/1.0 (${CORE_VERSION})`, accept: 'application/octet-stream' },
      signal: controller.signal,
    });
    if (!response.ok || response.body === null) return false;
    const declared = Number(response.headers.get('content-length') ?? '');
    if (Number.isFinite(declared) && declared > 0 && declared < GEODATA_MIN_BYTES) return false;

    const chunks = [];
    let written = 0;
    for await (const chunk of response.body) {
      // Reset on every chunk: a transfer that is moving is not failing, however
      // slow it is. Only a gap in the stream counts as a stall.
      armStallTimer();
      chunks.push(chunk);
      written += chunk.byteLength;
      if (Date.now() > deadline) throw new Error('budget');
    }
    if (written < GEODATA_MIN_BYTES) return false;

    const body = Buffer.concat(chunks);
    const expectedSha = GEODATA_SHA256[name];
    if (typeof expectedSha === 'string') {
      const actualSha = createHash('sha256').update(body).digest('hex');
      if (actualSha !== expectedSha) {
        // A size-valid but wrong file is exactly what the pin exists to catch:
        // reject it and let the next mirror try. Say so by name — the previous
        // version returned false silently, so a pin that stopped matching (the
        // failure mode this whole commit exists to fix) looked identical to a
        // mirror being down, and the only symptom was split routing quietly
        // turning itself off.
        log(`${name} 校验失败：期望 ${expectedSha.slice(0, 12)}…，实际 ${actualSha.slice(0, 12)}…`);
        return false;
      }
    }
    await writeFile(temporary, body, { mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => {});
    await rename(temporary, target);
    return true;
  } catch {
    await rm(temporary, { force: true }).catch(() => {});
    return false;
  } finally {
    if (stallTimer !== null) clearTimeout(stallTimer);
  }
}

/**
 * Make sure both rule databases are on disk.
 *
 * Returns the names that could NOT be provisioned. An empty array means the
 * China-direct rules can be used; a non-empty one means the caller must fall
 * back to plain MATCH routing, because a rule referencing a missing database
 * makes the core fail to start rather than skip the rule.
 *
 * @param {{log?: (message: string) => void}} [options]
 * @returns {Promise<string[]>} names that are still missing
 */
export async function ensureGeodata(options = {}) {
  const log = typeof options.log === 'function' ? options.log : () => {};
  const signal = options.signal;
  const deadline = Date.now() + GEODATA_BUDGET_MS;

  // An operator-supplied directory holds the files, but the core reads them from
  // its own -d directory: mihomo takes no flag for a rule-database path, and
  // `geox-url` refuses `file:` (measured: "unsupported protocol scheme file").
  // Checking the external directory and stopping there reported the databases as
  // ready while the core still found nothing, so it silently started its own
  // download — and because provisioning "succeeded", the caller never took the
  // documented fallback either. The two directories have to be reconciled, and
  // the only direction available is into DATA_DIR.
  if (geodataIsExternal()) {
    const missing = [];
    for (const name of Object.keys(GEODATA_SOURCES)) {
      const staged = path.join(geodataDir(), name);
      if (geodataVerified(name, geodataDir(), { trusted: true })) {
        // Copy rather than read in place: the core resolves rule databases
        // relative to -d, so the file has to physically be there. 27 MB takes
        // ~36 ms, and only when the bytes actually differ.
        try {
          // Compare the two files directly. An operator-staged database is
          // deliberately not the pinned digest, so `geodataVerified(name,
          // DATA_DIR)` is false on every connect and the 27 MB copy would run
          // again each time; identical bytes mean there is nothing to do.
          if (digestOf(staged) !== digestOf(path.join(DATA_DIR, name))) {
            await stageExternalGeodata(name, staged);
            log(`已复制 DSH_TUNNEL_GEODATA_DIR 的 ${name} 到内核目录`);
          }
        } catch (error) {
          // A read-only install location cannot receive the copy. Report it as
          // missing so the caller falls back to plain MATCH routing instead of
          // handing the core a rule whose database is not where it looks.
          log(`无法把 ${name} 复制到内核目录：${errorMessage(error)}`);
          missing.push(name);
        }
      } else if (geodataVerified(name, DATA_DIR)) {
        // External copy unusable, but a good one is already staged; keep it.
        log(`DSH_TUNNEL_GEODATA_DIR 中的 ${name} 不可用，沿用内核目录中的副本`);
      } else {
        log(`DSH_TUNNEL_GEODATA_DIR 中的 ${name} 缺失或过小`);
        missing.push(name);
      }
    }
    if (missing.length === 0) log('使用 DSH_TUNNEL_GEODATA_DIR 提供的规则数据库');
    return missing;
  }

  // Provisioned concurrently: the two databases are independent reads from
  // different mirrors, and serialising them would double the wait for nothing.
  // The shared deadline keeps the whole step inside one budget however many
  // mirrors are configured.
  const settled = await Promise.all(
    Object.keys(GEODATA_SOURCES).map(async (name) => {
      try {
        return [name, await provisionOne(name, deadline, log, signal)];
      } catch (error) {
        // Nothing here may take the connection down with it: the caller turns
        // the split rules off and connects anyway.
        log(`${name} 准备失败：${errorMessage(error)}`);
        return [name, false];
      }
    }),
  );

  return settled.filter(([, ready]) => !ready).map(([name]) => name);
}

/**
 * Put an operator-staged database where the core will look for it.
 *
 * Atomic like the download path: a partial copy left behind by a full disk or
 * an interrupted connect would be larger than the size floor and would then be
 * trusted on the next attempt, which is the same wedge this fix exists to
 * remove. The copy is skipped when source and destination are the same file —
 * a deployment that points `DSH_TUNNEL_GEODATA_DIR` at DATA_DIR would otherwise
 * copy a file onto itself.
 */
async function stageExternalGeodata(name, source) {
  const target = path.join(DATA_DIR, name);
  if (path.resolve(source) === path.resolve(target)) return;
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await chmod(DATA_DIR, 0o700).catch(() => {});
  const temporary = `${target}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    await copyFile(source, temporary);
    await chmod(temporary, 0o600).catch(() => {});
    await rename(temporary, target);
    await chmod(target, 0o600).catch(() => {});
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
}

/** Try every mirror for one database, stopping at the shared deadline. */
async function provisionOne(name, deadline, log, signal) {
  if (geodataReady(name)) return true;
  log(`缺少 ${name}，开始下载`);
  for (const url of GEODATA_SOURCES[name]) {
    if (signal !== undefined && signal !== null && signal.aborted) {
      log(`${name} 下载被取消`);
      return false;
    }
    if (Date.now() >= deadline) {
      log(`${name} 已超出下载预算，跳过剩余源`);
      return false;
    }
    // Host only: the mirrors differ by where they cache the same file, and the
    // full path is noise in a log line.
    const host = url.includes('//') ? url.split('/')[2] : url;
    if (await downloadGeodata(name, url, deadline, signal, log)) {
      log(`${name} 下载完成（${host}）`);
      return true;
    }
    log(`${name} 从 ${host} 下载失败`);
  }
  return false;
}

/**
 * Whether every routing database is already on disk.
 *
 * The UI uses this to tell a first connection (which has to fetch them) from a
 * repeat one; without it the first connect looks like an unexplained wait.
 */
export function geodataStatus() {
  return Object.keys(GEODATA_SOURCES).every((name) => geodataReady(name));
}

/** Write the generated configuration with owner-only permissions. */
export async function writeConfig(text) {
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await chmod(DATA_DIR, 0o700).catch(() => {});
  await writeFile(CONFIG_PATH, text, { mode: 0o600 });
  await chmod(CONFIG_PATH, 0o600).catch(() => {});
}

/** Remove the configuration, which contains node credentials. */
export async function removeConfig() {
  await rm(CONFIG_PATH, { force: true }).catch(() => {});
}

/** Call the local Clash-compatible API. */
export async function coreFetch(apiPort, secret, resource, init = {}) {
  const headers = {
    authorization: `Bearer ${secret}`,
    ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
    ...init.headers,
  };
  const response = await fetch(`http://127.0.0.1:${apiPort}${resource}`, {
    ...init,
    headers,
    signal: init.signal ?? AbortSignal.timeout(6_000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`mihomo API ${response.status}: ${text.slice(0, 300)}`);
  if (text.trim() === '') return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Wait until the core API answers, or fail with the process' stderr. */
export async function waitForCore(apiPort, secret, exitState) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (exitState.exited) throw new Error(`mihomo 内核启动失败：${exitState.detail || '进程已退出'}`);
    try {
      const version = await coreFetch(apiPort, secret, '/version', { signal: AbortSignal.timeout(1_200) });
      if (version && typeof version === 'object') return version;
    } catch {
      // Not ready yet.
    }
    await sleep(120);
  }
  throw new Error('mihomo 内核启动超时');
}

/** Wait for the generated select group to appear after the API is up. */
export async function waitForGroup(apiPort, secret, group, exitState) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (exitState.exited) throw new Error(`mihomo 内核启动失败：${exitState.detail || '进程已退出'}`);
    try {
      const info = await coreFetch(apiPort, secret, `/proxies/${encodeURIComponent(group)}`, {
        signal: AbortSignal.timeout(1_500),
      });
      if (info !== null && typeof info === 'object' && Array.isArray(info.all)) return info;
    } catch {
      // The selector is installed right after the API starts answering.
    }
    await sleep(100);
  }
  throw new Error('mihomo 代理组未就绪');
}

/**
 * The core's own last words, for the error line.
 *
 * mihomo writes everything to **stdout** and leaves stderr empty — measured on
 * v1.19.33: a fatal config error produced 952 bytes on stdout and 0 on stderr,
 * and a clean start produced 610 and 0. Reading only stderr therefore returned
 * an empty string on every failure, and the caller's `detail || '退出码 N'`
 * collapsed every distinct cause — a missing rule database, a busy port, a
 * malformed config — into the same "退出码 1". Both streams are read, stdout
 * first because that is where the content is.
 */
export async function readCoreLog(handle, maxChars = 1_500) {
  const read = (stream) => {
    try {
      const chunk = handle?.collected?.[stream]?.readFrom(0);
      if (chunk && typeof chunk.text === 'string') return chunk.text.trim();
    } catch {
      // The collector may not be available after a failed spawn.
    }
    return '';
  };
  const stdout = read('stdout');
  const stderr = read('stderr');
  const combined = stdout === '' ? stderr : stderr === '' ? stdout : `${stdout}\n${stderr}`;
  return combined.slice(-maxChars);
}

/**
 * Run the core's own configuration check (`mihomo -t`) and translate what it
 * says into something a user can act on.
 *
 * The core refuses the *whole* file over one bad proxy, and its stderr names
 * only a zero-based index (`proxy 0: unsupport proxy type: x`). Feeding that to
 * the settings page is what made "内核启动失败" unreadable: it says something is
 * wrong, never which node or why. Checking here, before the real start, turns
 * that into `第 3 个节点（"香港 01"）使用了此内核不支持的类型 "xyz"` and lets the
 * caller drop the offending nodes and retry instead of failing outright.
 *
 * The check runs before every connect (index.js calls it unconditionally).
 * It costs one extra process start, measured at ~56–64 ms on Windows for a
 * 4-node file and ~90 ms for a 200-node file — an acceptable price for turning
 * "内核启动失败" into a per-node diagnosis before the real start.
 *
 * @param {string} corePath  Absolute path to the core binary.
 * @param {{ cwd?: string, argv?: string[] }} [options]
 * @returns {Promise<{ ok: boolean, problems: { index: number, message: string }[], raw: string }>}
 */
export async function testConfig(corePath, options = {}) {
  const cwd = options.cwd ?? DATA_DIR;
  const argv = options.argv ?? [corePath, '-t', '-d', cwd, '-f', CONFIG_PATH];
  const runner = options.runner;
  if (typeof runner !== 'function') {
    // The host owns process creation. A plugin that reaches for
    // node:child_process itself escapes the harness's supervision — and in a
    // restricted host the call simply fails. Callers pass their subprocess
    // service in; without one there is no check to run, which the caller treats
    // as "unknown" rather than "bad configuration".
    return { ok: true, problems: [], raw: '', skipped: true };
  }
  if (options.signal?.aborted === true) return { ok: true, problems: [], raw: '', skipped: true };
  const result = await runner(argv, cwd, options.signal);
  // Aborted mid-check (the user pressed Disconnect): the empty output that
  // follows is not a verdict on the file, so reporting it as "the core rejected
  // the config" would invent a problem instead of the one that happened.
  if (options.signal?.aborted === true) return { ok: true, problems: [], raw: '', skipped: true };
  const output = typeof result?.output === 'string' ? result.output : '';
  return {
    ok: result?.code === 0 && /test is successful/.test(output),
    problems: parseCoreConfigErrors(output),
    raw: output.slice(-4_000),
    skipped: false,
  };
}

/**
 * Collect a subprocess handle's output into the shape {@link testConfig} reads.
 *
 * DSH's `subprocess.spawn` hands back a handle whose collected streams are read
 * after exit; this adapter keeps that contract out of the config-check logic so
 * the parsing and the translation stay testable on their own.
 *
 * @param {{ spawn: (options: Record<string, unknown>) => any }} service
 * @param {string[]} argv
 * @param {string} cwd
 * @param {{ env?: Record<string, string> }} [options]
 * @returns {(argv: string[], cwd: string) => Promise<{ code: number, output: string }>}
 */
export function makeConfigRunner(service, options = {}) {
  return async (argv, cwd, signal) => {
    const handle = service.spawn({
      argv,
      cwd,
      env: options.env ?? { HOME: cwd, TMPDIR: cwd },
      stdio: {
        stdin: 'ignore',
        stdout: { maxBytes: 256 * 1024 },
        stderr: { maxBytes: 256 * 1024 },
      },
      graceMs: 2_000,
      // The check spawns the same binary the real start does, and a rejected
      // config is not the only slow path: a file whose rules reference an
      // unprovisioned database makes the core go and download it, measured at
      // 90 s before it gives up. Without the signal, pressing Disconnect during
      // that window does nothing and connect stays blocked.
      signal,
    });
    let code = -1;
    try {
      const outcome = await handle.done;
      code = typeof outcome?.exitCode === 'number' ? outcome.exitCode : -1;
    } catch {
      code = -1;
    }
    // Read both streams through the handle's own collectors: the check writes
    // its verdict to stderr and the diagnostics that explain a rejection sit
    // there too, so neither stream alone is enough.
    const read = (stream) => {
      try {
        const chunk = handle?.collected?.[stream]?.readFrom?.(0);
        if (chunk && typeof chunk.text === 'string' && chunk.text.trim() !== '') return chunk.text.trim();
      } catch {
        // Collector unavailable after a failed spawn.
      }
      return '';
    };
    const output = [read('stderr'), read('stdout')].filter((part) => part !== '').join('\n');
    return { code, output };
  };
}

/**
 * Extract `proxy <index>: <message>` lines from the core's check output.
 *
 * The check emits either a JSON document or `logrus` lines depending on build
 * and version, so both shapes are read. Anything unrecognised is kept as a
 * problem with index -1 rather than dropped: an unknown failure is still a
 * failure, and hiding it would put us back where we started.
 *
 * @param {string} output
 * @returns {{ index: number, message: string }[]}
 */
export function parseCoreConfigErrors(output) {
  if (typeof output !== 'string' || output.trim() === '') return [];
  const problems = [];
  for (const line of output.split(/\r?\n/)) {
    const match = /proxy (\d+):\s*(.+?)\s*$/.exec(line);
    if (match !== null) {
      // The same message arrives quoted when it comes out of a JSON document
      // and bare from logrus, so trailing quotes and the closing brace are
      // trimmed rather than assumed absent.
      const message = match[2].replace(/["}\s]+$/, '').trim();
      if (message !== '') problems.push({ index: Number(match[1]), message });
      continue;
    }
    const generic = /level=error msg="([^"]+)"/.exec(line);
    if (generic !== null) {
      const message = generic[1].trim();
      // The per-proxy lines above are more specific; only keep this when it is
      // not a repeat of one of them.
      if (message !== '' && !/^proxy \d+:/.test(message)) problems.push({ index: -1, message });
    }
  }
  return problems;
}

/**
 * Turn a parsed core problem into a sentence naming the node it belongs to.
 *
 * @param {{ index: number, message: string }} problem
 * @param {{ name?: string, type?: string }[]} nodes
 * @returns {string}
 */
export function describeCoreProblem(problem, nodes) {
  const node = problem.index >= 0 ? nodes[problem.index] : undefined;
  const who = node === undefined
    ? ''
    : `第 ${problem.index + 1} 个节点${node.name ? `（"${node.name}"）` : ''}${node.type ? `，类型 ${node.type}` : ''}：`;
  const message = problem.message;
  const unsupported = /unsupport proxy type:\s*(.+)$/.exec(message);
  if (unsupported !== null) {
    return `${who}此版本 mihomo 内核不支持节点类型 "${unsupported[1].trim()}"`;
  }
  const unset = /has unset fields:\s*(.+)$/.exec(message);
  if (unset !== null) {
    return `${who}缺少必填字段 ${unset[1].trim()}`;
  }
  return `${who}${message}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(error) {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause instanceof Error ? `: ${error.cause.message}` : '';
  return `${message}${cause}`;
}
