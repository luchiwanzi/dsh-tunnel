/**
 * IP / hostname safety checks for subscription URLs (SSRF guard).
 *
 * The blocked ranges mirror the DIRECT rules in the generated mihomo config so
 * that a subscription URL can never target the local host, a private network,
 * a link-local address, or a cloud metadata endpoint. Hostnames are checked
 * after DNS resolution to resist rebinding.
 */

/**
 * Blocked IPv4 ranges, in CIDR form.
 *
 * Only IPv4: {@link isBlockedIpv4} matches these against a parsed 32-bit
 * integer, and an IPv6 entry here would never be read — the IPv6 rules are
 * expressed as bit tests in {@link isBlockedIpv6} instead, because they are
 * easier to read and to get right there than as a string prefix match.
 * Keeping the two families in separate lists is what stops one of them from
 * quietly becoming dead configuration.
 */
export const BLOCKED_CIDRS = [
  '127.0.0.0/8', // 回环
  '0.0.0.0/8', // 本网络（"this network"）
  '10.0.0.0/8', // 私有
  '172.16.0.0/12', // 私有
  '192.168.0.0/16', // 私有
  '169.254.0.0/16', // 链路本地 / 云元数据
  '100.64.0.0/10', // 运营商级 NAT
];

/**
 * Blocked IPv6 ranges, in CIDR form, documented here for readers.
 *
 * {@link isBlockedIpv6} implements these as bit tests rather than reading this
 * list, so **this array is descriptive, not consulted**. It is exported anyway
 * because the rules belong somewhere a reviewer can read them as a set; a test
 * pins the two representations against each other so the description cannot
 * drift from the implementation.
 */
export const BLOCKED_CIDRS_V6 = [
  '::/128', // 未指定地址（连接它会落到本机）
  '::1/128', // 回环
  'fc00::/7', // 唯一本地地址 ULA
  'fe80::/10', // 链路本地
  '::ffff:0:0/96', // IPv4-mapped，按内嵌的 IPv4 判断
];

// 禁止直接访问的特殊主机名（如云元数据域名）。
export const BLOCKED_HOSTS = new Set(['localhost', 'localhost.localdomain', 'metadata.google.internal']);

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** 严格解析点分十进制 IPv4，非法返回 null。 */
export function parseIpv4(value) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  return m ? ipv4ToInt(value) : null;
}

function ipv6ToBytes(ip) {
  // 归一化点分十进制 IPv4-mapped 形式（如 ::ffff:127.0.0.1），
  // 否则 parseHextets 会因含 '.' 的段返回 null，导致内部地址被放行。
  const mapped = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(ip.toLowerCase());
  const normalized = mapped !== null
    ? `${mapped[1]}${ipv4ToHextets(mapped[2])}`
    : ip.toLowerCase();
  if (normalized.includes('::')) {
    const [head, tail] = normalized.split('::');
    const headParts = head === '' ? [] : head.split(':').filter(Boolean);
    const tailParts = tail === '' ? [] : tail.split(':').filter(Boolean);
    const zeroCount = 8 - headParts.length - tailParts.length;
    if (zeroCount < 0) return null;
    const parts = [...headParts, ...Array(zeroCount).fill('0'), ...tailParts];
    if (parts.length !== 8) return null;
    return parseHextets(parts);
  }
  const parts = normalized.split(':');
  if (parts.length !== 8) return null;
  return parseHextets(parts);
}

/** 把点分十进制 IPv4 转成两个 hextet（用于 IPv4-mapped 归一化）。 */
function ipv4ToHextets(ip) {
  const int = ipv4ToInt(ip);
  if (int === null) return '';
  const high = (int >>> 16).toString(16);
  const low = (int & 0xffff).toString(16);
  return `${high}:${low}`;
}

// 把 8 个 16 位 hextet 严格解析为数值；任一非法段都返回 null，避免静默丢弃。
function parseHextets(parts) {
  const bytes = new Array(8);
  for (let index = 0; index < 8; index += 1) {
    const segment = parts[index];
    // 严格校验：仅接受 1-4 位十六进制，避免 parseInt 对 "12g"、"1.5" 等部分匹配。
    if (!/^[0-9a-f]{1,4}$/.test(segment)) return null;
    bytes[index] = parseInt(segment, 16);
  }
  return bytes;
}

function cidrContainsIpv4(cidr, ipInt) {
  const [base, prefix] = cidr.split('/');
  const baseInt = ipv4ToInt(base);
  if (baseInt === null || ipInt === null) return false;
  const bits = Number(prefix);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function isBlockedIpv4(ip) {
  const int = parseIpv4(ip);
  if (int === null) return false;
  return BLOCKED_CIDRS.some((cidr) => cidr.includes('.') && cidrContainsIpv4(cidr, int));
}

function isBlockedIpv6(ip) {
  const bytes = ipv6ToBytes(ip);
  if (bytes === null || bytes.length !== 8) return false;
  // ::（未指定地址 / ::/128）：全零。不是回环字面量，但连接它等于连本机 ——
  // 在 Linux 上 `connect` 到 :: 会落到回环接口，所以它是一条通往内网的路，
  // 必须和 ::1 同等对待。Windows 上该连接会失败，但不能依赖运行平台。
  if (bytes.every((v) => v === 0)) return true;
  // ::1（回环）
  if (bytes.every((v, i) => (i < 7 ? v === 0 : v === 1))) return true;
  // ::ffff:0:0/96（IPv4-mapped）：后 32 位是 IPv4，交给 IPv4 判断。
  if (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0 && bytes[4] === 0 && bytes[5] === 0xffff) {
    const ipv4 = `${bytes[6] >> 8}.${bytes[6] & 0xff}.${bytes[7] >> 8}.${bytes[7] & 0xff}`;
    return isBlockedIpv4(ipv4);
  }
  // fc00::/7（私有 ULA）：首 hextet 高 7 位为 1111110
  if ((bytes[0] & 0xfe00) === 0xfc00) return true;
  // fe80::/10（链路本地）：首 hextet 高 10 位为 1111111010
  if ((bytes[0] & 0xffc0) === 0xfe80) return true;
  // 以下三类是「IPv4 地址内嵌在 IPv6 里」的其余写法。它们和 IPv4-mapped 一样
  // 承载一个 IPv4 目标，因此必须按内嵌的 IPv4 判定 —— 否则 ::7f00:1 这类
  // 指向回环的地址会被放行。前两类只有在部署了相应路由时才是通路
  // （NAT64 网关、6to4 中继），但判定不能依赖运行平台的网络配置。
  const embedded = embeddedIpv4(bytes);
  if (embedded !== null) return isBlockedIpv4(embedded);
  return false;
}

/**
 * The IPv4 address an IPv6 form embeds, or `null` when it embeds none.
 *
 * Covered forms, with the prefix that identifies each:
 *
 * - `::ffff:0:0/96` — IPv4-mapped (already handled by the caller).
 * - `::/96` — IPv4-compatible, deprecated but still parseable: `::7f00:1`.
 * - `::ffff:0:0:0/96` — IPv4-translated: `::ffff:0:127.0.0.1`.
 * - `64:ff9b::/96` — NAT64 well-known prefix: `64:ff9b::7f00:1`.
 * - `2002::/16` — 6to4: the IPv4 address sits in hextets 1-2: `2002:7f00:1::`.
 *
 * Only the embedded IPv4 is returned; whether it is *blocked* is the caller's
 * decision, so a NAT64 address wrapping a public IPv4 stays usable.
 *
 * @param {number[]} bytes The eight hextets.
 * @returns {string | null}
 */
function embeddedIpv4(bytes) {
  const toIpv4 = (high, low) => `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
  const zeroUntil = (limit) => bytes.slice(0, limit).every((v) => v === 0);

  // ::/96（IPv4-compatible）：前 6 个 hextet 全零。`::` 与 `::1` 已在上面
  // 拦截，这里剩下的必然内嵌一个非零 IPv4。
  if (zeroUntil(6)) return toIpv4(bytes[6], bytes[7]);

  // ::ffff:0:0:0/96（IPv4-translated）：::ffff:0:<ipv4>
  if (zeroUntil(4) && bytes[4] === 0xffff && bytes[5] === 0) {
    return toIpv4(bytes[6], bytes[7]);
  }

  // 64:ff9b::/96（NAT64）：前 6 个 hextet 固定为 0064:ff9b:0000:0000:0000:0000
  if (bytes[0] === 0x0064 && bytes[1] === 0xff9b && bytes.slice(2, 6).every((v) => v === 0)) {
    return toIpv4(bytes[6], bytes[7]);
  }

  // 2002::/16（6to4）：IPv4 在 hextet 1-2
  if (bytes[0] === 0x2002) return toIpv4(bytes[1], bytes[2]);

  return null;
}

/** 判断一个 IP 字面量（IPv4 或 IPv6）是否指向被禁止的内部地址。 */
export function isBlockedIp(ip) {
  if (ip.includes(':')) return isBlockedIpv6(ip);
  return isBlockedIpv4(ip);
}

/** 判断主机名是否为禁止直接访问的特殊域名。 */
export function isBlockedHostname(host) {
  return BLOCKED_HOSTS.has(host);
}
