/**
 * mihomo (Clash.Meta) process lifecycle: binary provisioning, config
 * generation, readiness checks, and the local Clash API.
 */

import { existsSync, statSync } from 'node:fs';
import { chmod, mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createServer, isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { stringify as stringifyYaml } from 'yaml';

export const CORE_VERSION = 'v1.19.33';
const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_DIR = path.join(PLUGIN_ROOT, '.data');
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

/** Resolve the core path, honoring a caller override. */
export function resolveCorePath(customPath) {
  if (typeof customPath === 'string' && customPath.trim() !== '') return customPath.trim();
  if (existsSync(CORE_PATH)) return CORE_PATH;
  return packagedCorePath() ?? CORE_PATH;
}

/** Return an installed core, downloading the Linux release as a fallback. */
export async function ensureCore(customPath, onDownloading) {
  const target = resolveCorePath(customPath);
  if (existsSync(target)) return target;

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

/** A database is usable when it exists and is at least the size floor. */
function geodataReady(name) {
  try {
    return statSync(geodataPath(name)).size >= GEODATA_MIN_BYTES;
  } catch {
    return false;
  }
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

  // With an operator-supplied directory there is nothing to fetch: the files are
  // theirs to place and to keep current, so report what is present and let the
  // caller decide. Downloading over them would be worse than useless — it would
  // overwrite the very copy they staged.
  if (geodataIsExternal()) {
    const external = Object.keys(GEODATA_SOURCES).filter((name) => !geodataReady(name));
    if (external.length > 0) {
      log(`DSH_TUNNEL_GEODATA_DIR 中缺少：${external.join('、')}`);
    } else {
      log('使用 DSH_TUNNEL_GEODATA_DIR 提供的规则数据库');
    }
    return external;
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

export async function readCoreLog(handle) {
  try {
    const stderr = handle?.collected?.stderr?.readFrom(0);
    if (stderr && stderr.text.trim() !== '') return stderr.text.trim().slice(-1_500);
  } catch {
    // The collector may not be available after a failed spawn.
  }
  return '';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(error) {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause instanceof Error ? `: ${error.cause.message}` : '';
  return `${message}${cause}`;
}
