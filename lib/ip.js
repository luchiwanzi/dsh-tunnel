/**
 * IP / hostname safety checks for subscription URLs (SSRF guard).
 *
 * The blocked ranges mirror the DIRECT rules in the generated mihomo config so
 * that a subscription URL can never target the local host, a private network,
 * a link-local address, or a cloud metadata endpoint. Hostnames are checked
 * after DNS resolution to resist rebinding.
 */

// 私有 / 保留网段（与 mihomo 配置的直连规则保持一致）。
export const BLOCKED_CIDRS = [
  '127.0.0.0/8',
  '0.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
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
  return false;
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
