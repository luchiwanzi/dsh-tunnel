/**
 * Subscription parsing for the Tunnel plugin.
 *
 * Supports:
 *  - Clash / Clash.Meta / mihomo YAML documents with an inline `proxies` list.
 *  - Base64-encoded or plain URI lists (ss, vmess, trojan, vless, hysteria2,
 *    tuic, socks5, http).
 *
 * Only node definitions are kept. Subscription-provided groups and rules are
 * deliberately ignored: the plugin owns a single deterministic group so the
 * user can select a node from the management page.
 */

import { parse as parseYaml } from 'yaml';

const MAX_NODES = 500;

/**
 * Proxy types the bundled mihomo core actually accepts, with the fields it
 * refuses to load without.
 *
 * This table exists because of how the core reacts to a single bad node: it
 * rejects the *whole* configuration, and the only thing it says is
 * `unsupport proxy type: x` or `has unset fields: a, b` on stderr. So one
 * unknown protocol anywhere in a subscription — a provider rolling out a new
 * one, a typo, a YAML entry that is not really a proxy — turns "Connect" into
 * "内核启动失败" with no mention of which node or which field.
 *
 * The types and required fields here were measured against the pinned core
 * (mihomo v1.19.33) by feeding it one proxy at a time. `ssr`/`vmess`/
 * `hysteria` `snell`/`wireguard`/`ssh`/`mieru` are supported by the core but
 * need their own mandatory fields, which are listed so a node missing them is
 * reported as such instead of surviving to the core.
 *
 * A type absent from this table is dropped at parse time, with a warning that
 * names it. That is deliberately lossy: the alternative is a subscription that
 * cannot connect at all because one of two hundred nodes used a newer protocol.
 */
const SUPPORTED_TYPES = new Map([
  ['ss', []],
  ['ssr', []],
  ['vmess', []],
  ['vless', []],
  ['trojan', []],
  ['hysteria', []],
  ['hysteria2', []],
  ['tuic', []],
  ['snell', []],
  ['socks5', []],
  ['http', []],
  ['wireguard', []],
  ['ssh', []],
  ['mieru', []],
  ['anytls', []],
  // Not transport proxies but legal `proxies` entries in mihomo.
  ['direct', []],
  ['dns', []],
  ['reject', []],
]);

/**
 * Proxy attributes the number of nodes that cited each one.
 *
 * @typedef {{ type: string, name: string }} DroppedNode
 */

/** U+0000-U+001F and U+007F-U+009F: the set the former literal regex rejected. */
const CONTROL_CHARACTER = /\p{Cc}/u;

/**
 * True when `value` carries a control character other than tab, CR or LF.
 * Rejects binary payloads that happen to decode as base64.
 */
function hasControlChars(value) {
  for (const character of value) {
    if (character === '\t' || character === '\n' || character === '\r') continue;
    if (CONTROL_CHARACTER.test(character)) return true;
  }
  return false;
}

/** Parse the de-facto `subscription-userinfo` response header. */
export function parseUserinfo(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  const info = {};
  for (const part of value.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim().toLowerCase();
    const number = Number(part.slice(index + 1).trim());
    if (!['upload', 'download', 'total', 'expire'].includes(key)) continue;
    if (Number.isFinite(number) && number >= 0) info[key] = number;
  }
  return Object.keys(info).length === 0 ? null : info;
}

/** Parse a subscription body into normalized proxy nodes. */
export function parseSubscription(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new Error('配置内容为空');
  }

  const input = text.trim();
  if (/^\s*(proxies|proxy-groups|proxy-providers)\s*:/m.test(input)) {
    return parseClash(input);
  }

  const decoded = decodeBase64Text(input);
  if (decoded !== null && /^\s*(proxies|proxy-groups|proxy-providers)\s*:/m.test(decoded)) {
    return parseClash(decoded);
  }
  const body = decoded !== null && decoded.includes('://') ? decoded : input;
  return parseUriList(body);
}

/**
 * Turn the skipped-node decisions into sentences a user can act on.
 *
 * Grouped by reason and by type, because a subscription with 200 nodes using
 * one unsupported protocol should read as `200 个节点使用了此版本内核不支持的类型：(x)`
 * — not as 200 identical lines. Names are quoted only when there are few enough
 * to stay readable; past that the counts are what matters.
 *
 * @param {{ reason: string, name: string, type: string, detail?: string[] }[]} skipped
 * @returns {string[]}
 */
function describeSkipped(skipped) {
  if (skipped.length === 0) return [];
  const warnings = [];

  const unsupported = new Map();
  for (const item of skipped) {
    if (item.reason !== 'unsupported-type') continue;
    const type = item.type === '' ? '(空)' : item.type;
    const entry = unsupported.get(type) ?? [];
    entry.push(item.name);
    unsupported.set(type, entry);
  }
  if (unsupported.size > 0) {
    // Named per type, and with the node names when there are few enough to
    // list: the point of this sentence is that the user can go and look at the
    // entry the provider is serving them, not just learn a count.
    const parts = [...unsupported.entries()]
      .sort((a, b) => b[1].length - a[1].length)
      .map(([type, names]) => `${names.length} 个 ${type} 节点${names.length <= 3 ? `（${names.join('、')}）` : ''}`);
    warnings.push(`已跳过 ${parts.join('，')}：该协议此版本 mihomo 内核不支持，保留会导致内核拒绝整份配置`);
  }

  const missing = new Map();
  for (const item of skipped) {
    if (item.reason !== 'missing-fields') continue;
    const key = `${item.type || '(无类型)'}:${(item.detail ?? []).join(',')}`;
    const entry = missing.get(key) ?? { type: item.type, fields: item.detail ?? [], names: [] };
    entry.names.push(item.name);
    missing.set(key, entry);
  }
  for (const entry of missing.values()) {
    warnings.push(
      `已跳过 ${entry.names.length} 个 ${entry.type || '(无类型)'} 节点（${entry.fields.join('、')} 无效${
        entry.names.length <= 5 ? `：${entry.names.join('、')}` : ''
      }）`,
    );
  }

  const malformed = skipped.filter((item) => item.reason === 'shape').length;
  if (malformed > 0) warnings.push(`已跳过 ${malformed} 个格式不正确的节点条目`);

  return warnings;
}

function parseClash(text) {
  let document;
  try {
    document = parseYaml(text, { maxAliasCount: 100, uniqueKeys: false, prettyErrors: false });
  } catch (error) {
    throw new Error(`Clash 配置解析失败：${errorMessage(error)}`);
  }

  const rawList = Array.isArray(document) ? document : document?.proxies;
  if (!Array.isArray(rawList)) {
    throw new Error('内容中没有找到 proxies 节点列表，请确认是 Clash 配置');
  }
  const hosts = normalizeHosts(document?.hosts);

  const nodes = [];
  const skipped = [];
  for (const raw of rawList) {
    const result = normalizeClashNode(raw);
    if (result.ok) nodes.push(result.node);
    else skipped.push(result);
  }

  const warnings = describeSkipped(skipped);
  if (nodes.length === 0) {
    // Nothing survived, so the per-node warnings above are the only thing that
    // explains why. Putting them in the thrown message is the difference
    // between "订阅中的节点均缺少必要字段" and knowing that every node used a
    // protocol this build of the core does not carry.
    const detail = warnings.length > 0 ? `：${warnings.join('；')}` : '';
    throw new Error(`订阅中没有可用的节点${detail}`);
  }
  return finish(nodes, 'clash', warnings, hosts);
}

/**
 * Keep the Clash `hosts` overrides. Many providers publish pseudo hostnames in
 * `server` and map them to real CDN names here; without the map those nodes
 * cannot resolve at all.
 */
function normalizeHosts(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return {};
  const hosts = {};
  for (const [key, target] of Object.entries(value)) {
    if (key === '' || key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof target !== 'string' || target.trim() === '') continue;
    hosts[key] = target.trim();
  }
  return hosts;
}

/**
 * Normalise one `proxies` entry, or say precisely why it cannot be used.
 *
 * The return shape is a decision rather than a value, because "null" erased
 * every distinction the caller needs: a node that is missing its port and a
 * node speaking a protocol this build of the core does not have produce the
 * same silence today, and they need different sentences in front of the user.
 *
 * @param {unknown} raw
 * @returns {{ ok: true, node: Record<string, unknown> }
 *   | { ok: false, reason: 'shape' | 'missing-fields' | 'unsupported-type', name: string, type: string, detail?: string[] }}
 */
function normalizeClashNode(raw) {
  const describe = raw !== null && typeof raw === 'object' && !Array.isArray(raw)
    ? `${String(raw.name || raw.type || '未命名节点')}`.slice(0, 60)
    : '未命名节点';
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'shape', name: describe, type: '' };
  }
  let clone;
  try {
    clone = JSON.parse(JSON.stringify(raw));
  } catch {
    return { ok: false, reason: 'shape', name: describe, type: '' };
  }
  const type = String(clone.type || '').trim().toLowerCase();
  if (!SUPPORTED_TYPES.has(type)) {
    // An empty type is the same failure one step earlier: the core would report
    // it as an unsupported type as well, so it is grouped here rather than
    // being called a missing field.
    return { ok: false, reason: 'unsupported-type', name: describe, type };
  }
  const name = cleanName(clone.name || `${type} ${clone.server || ''}`);
  const server = String(clone.server || '').trim();
  const port = Number(clone.port);
  const missing = [];
  if (name === '') missing.push('name');
  if (server === '') missing.push('server');
  if (!validPort(port)) missing.push('port');
  for (const field of SUPPORTED_TYPES.get(type) ?? []) {
    if (clone[field] === undefined || clone[field] === '') missing.push(field);
  }
  if (missing.length > 0) {
    return { ok: false, reason: 'missing-fields', name: describe, type, detail: missing };
  }
  return { ok: true, node: { ...clone, name, type, server, port } };
}

function parseUriList(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#') && line.includes('://'));

  const nodes = [];
  const warnings = [];
  let unsupported = 0;
  for (const line of lines) {
    const node = parseProxyUri(line);
    if (node === null) {
      unsupported += 1;
      continue;
    }
    nodes.push(node);
  }

  if (unsupported > 0) warnings.push(`${unsupported} 个节点使用了暂不支持的协议或参数，已跳过`);
  if (nodes.length === 0) {
    throw new Error('无法识别内容格式：请使用 Clash YAML，或包含 ss/vmess/trojan/vless/hysteria2/tuic/socks5/http 节点的链接列表');
  }
  return finish(nodes, 'uri', warnings);
}

function parseProxyUri(line) {
  const scheme = line.slice(0, line.indexOf('://')).toLowerCase();
  try {
    switch (scheme) {
      case 'ss':
        return parseShadowsocks(line);
      case 'vmess':
        return parseVmess(line);
      case 'trojan':
        return parseTrojan(line);
      case 'vless':
        return parseVless(line);
      case 'hysteria2':
      case 'hy2':
        return parseHysteria2(line);
      case 'tuic':
        return parseTuic(line);
      case 'socks':
      case 'socks5':
      case 'socks5h':
        return parseSocks(line);
      case 'http':
      case 'https':
        return parseHttpProxy(line);
      default:
        return null;
    }
  } catch {
    return null;
  }
}

function parseShadowsocks(uri) {
  const hash = uri.indexOf('#');
  const name = hash === -1 ? '' : decodeFragment(uri.slice(hash + 1));
  let body = hash === -1 ? uri.slice(5) : uri.slice(5, hash);
  let query = '';
  const question = body.indexOf('?');
  if (question !== -1) {
    query = body.slice(question + 1);
    body = body.slice(0, question);
  }

  let method;
  let password;
  let host;
  let port;

  if (body.includes('@')) {
    const at = body.lastIndexOf('@');
    let userinfo = body.slice(0, at);
    const hostport = splitHostPort(body.slice(at + 1));
    if (hostport === null) return null;
    const decodedUserinfo = decodeBase64Text(userinfo);
    if (decodedUserinfo !== null && decodedUserinfo.includes(':')) userinfo = decodedUserinfo;
    else userinfo = decodeURIComponent(userinfo);
    const colon = userinfo.indexOf(':');
    if (colon === -1) return null;
    method = userinfo.slice(0, colon);
    password = userinfo.slice(colon + 1);
    host = hostport.host;
    port = hostport.port;
  } else {
    const decoded = decodeBase64Text(body);
    if (decoded === null) return null;
    const at = decoded.lastIndexOf('@');
    if (at === -1) return null;
    const credentials = decoded.slice(0, at);
    const hostport = splitHostPort(decoded.slice(at + 1));
    if (hostport === null) return null;
    const colon = credentials.indexOf(':');
    if (colon === -1) return null;
    method = credentials.slice(0, colon);
    password = credentials.slice(colon + 1);
    host = hostport.host;
    port = hostport.port;
  }

  password = decodeURIComponent(password);
  method = decodeURIComponent(method).trim();
  if (method === '' || password === '' || !validPort(port)) return null;

  const node = {
    name: cleanName(name || `ss ${host}:${port}`),
    type: 'ss',
    server: host,
    port,
    cipher: method,
    password,
    udp: true,
  };

  if (query !== '') {
    const plugin = ssPlugin(query);
    if (plugin === null) return null;
    Object.assign(node, plugin);
  }
  return node;
}

function ssPlugin(query) {
  const params = new URLSearchParams(query);
  const plugin = params.get('plugin');
  if (!plugin) return {};
  const parts = plugin.split(';');
  const kind = parts.shift();
  const options = {};
  for (const part of parts) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    options[part.slice(0, index)] = part.slice(index + 1);
  }
  if (kind === 'obfs-local' || kind === 'simple-obfs') {
    return {
      plugin: 'obfs',
      'plugin-opts': {
        mode: options.obfs || 'http',
        host: options['obfs-host'] || '',
      },
    };
  }
  if (kind === 'v2ray-plugin') {
    return {
      plugin: 'v2ray-plugin',
      'plugin-opts': {
        mode: options.mode || 'websocket',
        host: options.host || '',
        path: options.path || '/',
        tls: options.tls === 'true',
      },
    };
  }
  return null;
}

function parseVmess(uri) {
  const payload = decodeBase64Text(uri.slice(8));
  if (payload === null) return null;
  const json = JSON.parse(payload);
  if (json === null || typeof json !== 'object') return null;
  const server = String(json.add || '').trim();
  const port = Number(json.port);
  const uuid = String(json.id || '').trim();
  if (server === '' || uuid === '' || !validPort(port)) return null;

  const node = {
    name: cleanName(json.ps || `vmess ${server}:${port}`),
    type: 'vmess',
    server,
    port,
    uuid,
    alterId: Number(json.aid || 0) || 0,
    cipher: String(json.scy || 'auto') || 'auto',
    udp: true,
  };

  const network = String(json.net || 'tcp');
  node.network = network;
  if (network === 'ws') {
    node['ws-opts'] = {
      path: String(json.path || '/'),
      headers: json.host ? { Host: String(json.host) } : {},
    };
  } else if (network === 'grpc') {
    node['grpc-opts'] = { 'grpc-service-name': String(json.path || '') };
  }

  if (json.tls === 'tls' || json.tls === true) {
    node.tls = true;
    node.servername = String(json.sni || json.host || server);
    if (json.skip_cert_verify === true || json.verify_cert === false) node['skip-cert-verify'] = true;
  }
  return node;
}

function parseTrojan(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, 443);
  const password = decodeURIComponent(url.username);
  if (server === '' || password === '' || !validPort(port)) return null;

  const query = url.searchParams;
  const network = query.get('type') || 'tcp';
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `trojan ${server}:${port}`),
    type: 'trojan',
    server,
    port,
    password,
    udp: true,
    network,
  };
  if (query.get('security') !== 'none') {
    node.tls = true;
    node.sni = query.get('sni') || query.get('peer') || server;
    if (query.get('allowInsecure') === '1' || query.get('insecure') === '1') node['skip-cert-verify'] = true;
  }
  if (network === 'ws') {
    node['ws-opts'] = {
      path: query.get('path') || '/',
      headers: query.get('host') ? { Host: query.get('host') } : {},
    };
  } else if (network === 'grpc') {
    node['grpc-opts'] = { 'grpc-service-name': query.get('serviceName') || '' };
  }
  return node;
}

function parseVless(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, 443);
  const uuid = decodeURIComponent(url.username);
  if (server === '' || uuid === '' || !validPort(port)) return null;

  const query = url.searchParams;
  const security = query.get('security') || 'none';
  const network = query.get('type') || 'tcp';
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `vless ${server}:${port}`),
    type: 'vless',
    server,
    port,
    uuid,
    udp: true,
    network,
  };
  if (query.get('flow')) node.flow = query.get('flow');
  if (security === 'tls' || security === 'reality') {
    node.tls = true;
    node.servername = query.get('sni') || query.get('host') || server;
    if (query.get('fp')) node['client-fingerprint'] = query.get('fp');
    if (query.get('allowInsecure') === '1' || query.get('insecure') === '1') node['skip-cert-verify'] = true;
  }
  if (security === 'reality') {
    const publicKey = query.get('pbk');
    const shortId = query.get('sid');
    if (publicKey) node['reality-opts'] = { 'public-key': publicKey, ...(shortId ? { 'short-id': shortId } : {}) };
  }
  if (network === 'ws') {
    node['ws-opts'] = {
      path: query.get('path') || '/',
      headers: query.get('host') ? { Host: query.get('host') } : {},
    };
  } else if (network === 'grpc') {
    node['grpc-opts'] = { 'grpc-service-name': query.get('serviceName') || '' };
  }
  return node;
}

function parseHysteria2(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, 443);
  const password = decodeURIComponent(url.username) || decodeURIComponent(url.password);
  if (server === '' || password === '' || !validPort(port)) return null;

  const query = url.searchParams;
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `hysteria2 ${server}:${port}`),
    type: 'hysteria2',
    server,
    port,
    password,
    udp: true,
  };
  if (query.get('sni')) node.sni = query.get('sni');
  if (query.get('insecure') === '1' || query.get('allowInsecure') === '1') node['skip-cert-verify'] = true;
  if (query.get('obfs')) {
    node.obfs = query.get('obfs');
    if (query.get('obfs-password')) node['obfs-password'] = query.get('obfs-password');
  }
  if (query.get('up')) node.up = query.get('up');
  if (query.get('down')) node.down = query.get('down');
  return node;
}

function parseTuic(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, 443);
  const uuid = decodeURIComponent(url.username);
  const password = decodeURIComponent(url.password);
  if (server === '' || uuid === '' || password === '' || !validPort(port)) return null;

  const query = url.searchParams;
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `tuic ${server}:${port}`),
    type: 'tuic',
    server,
    port,
    uuid,
    password,
    udp: true,
  };
  if (query.get('sni')) node.sni = query.get('sni');
  if (query.get('alpn')) node.alpn = query.get('alpn').split(',').filter(Boolean);
  if (query.get('congestion_control')) node['congestion-controller'] = query.get('congestion_control');
  if (query.get('udp_relay_mode')) node['udp-relay-mode'] = query.get('udp_relay_mode');
  if (query.get('allowInsecure') === '1' || query.get('insecure') === '1') node['skip-cert-verify'] = true;
  return node;
}

function parseSocks(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, 1080);
  if (server === '' || !validPort(port)) return null;
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `socks5 ${server}:${port}`),
    type: 'socks5',
    server,
    port,
    udp: true,
  };
  if (url.username) node.username = decodeURIComponent(url.username);
  if (url.password) node.password = decodeURIComponent(url.password);
  if (url.protocol === 'socks5h:') node['remote-dns-resolve'] = true;
  return node;
}

function parseHttpProxy(uri) {
  const url = new URL(uri);
  const server = hostOf(url);
  const port = portOf(url, url.protocol === 'https:' ? 443 : 80);
  if (server === '' || !validPort(port)) return null;
  const node = {
    name: cleanName(decodeFragment(url.hash.slice(1)) || `${url.protocol.slice(0, -1)} ${server}:${port}`),
    type: 'http',
    server,
    port,
  };
  if (url.username) node.username = decodeURIComponent(url.username);
  if (url.password) node.password = decodeURIComponent(url.password);
  if (url.protocol === 'https:') node.tls = true;
  return node;
}

function finish(nodes, format, warnings, hosts = {}) {
  const normalized = [];
  const used = new Set();
  for (const node of nodes) {
    if (normalized.length >= MAX_NODES) {
      warnings.push(`节点数量超过 ${MAX_NODES}，仅保留前 ${MAX_NODES} 个`);
      break;
    }
    const base = cleanName(node.name) || `${node.type} ${node.server}:${node.port}`;
    let name = base;
    let index = 2;
    while (used.has(name)) name = `${base} (${index++})`;
    used.add(name);
    // 标记禁用了证书校验的节点，供前端提示中间人风险。
    const insecure = node['skip-cert-verify'] === true;
    normalized.push({ ...node, name, insecure });
  }
  const insecureCount = normalized.filter((node) => node.insecure === true).length;
  if (insecureCount > 0) {
    warnings.push(`${insecureCount} 个节点禁用了证书校验（skip-cert-verify），存在中间人风险`);
  }
  return { nodes: normalized, format, warnings, hosts };
}

function decodeBase64Text(input) {
  let value = input.trim();
  if (value.startsWith('data:')) {
    const comma = value.indexOf(',');
    if (comma === -1) return null;
    value = value.slice(comma + 1);
  }
  value = value.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  while (value.length % 4 !== 0) value += '=';
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8');
    if (hasControlChars(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

function splitHostPort(value) {
  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close === -1) return null;
    const host = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (!rest.startsWith(':')) return null;
    return { host, port: Number(rest.slice(1)) };
  }
  const colon = value.lastIndexOf(':');
  if (colon === -1) return null;
  return { host: value.slice(0, colon), port: Number(value.slice(colon + 1)) };
}

function hostOf(url) {
  return url.hostname.replace(/^\[|\]$/g, '');
}

function portOf(url, fallback) {
  return url.port === '' ? fallback : Number(url.port);
}

function validPort(port) {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}

function cleanName(value) {
  return String(value ?? '')
    .replace(/\p{Cc}/gu, ' ')
    .trim()
    .slice(0, 80);
}

function decodeFragment(value) {
  if (value === '') return '';
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}