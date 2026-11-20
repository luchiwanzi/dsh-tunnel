/**
 * Host half of the DSH Tunnel plugin.
 *
 * One subscription becomes a local mihomo process. While connected, the
 * plugin installs DSH's process-wide outbound proxy policy, so the harness's
 * own `fetch` traffic (models, web tools, MCP) and future subprocesses use the
 * selected node. The system proxy and OS routing table are never touched.
 */

import { existsSync } from 'node:fs';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseSubscription, parseUserinfo } from './lib/subscription.js';
import { pinnedFetchAny } from './lib/pinned-fetch.js';
import { normalizeForVisit, resolveRedirect } from './lib/redirect-policy.js';
import { assertSafeTarget } from './lib/ssrf-guard.js';
import { describePinned, pinIpv6OnlyServers } from './lib/resolve.js';
import {
  buildConfig,
  CORE_VERSION,
  coreFetch,
  DATA_DIR,
  ensureCore,
  ensureGeodata,
  geodataStatus,
  allocatePorts,
  readCoreLog,
  removeConfig,
  resolveCorePath,
  waitForCore,
  waitForGroup,
  writeConfig,
} from './lib/mihomo.js';

const API_PATH = '/dsh-tunnel/api';
const STATE_PATH = path.join(DATA_DIR, 'state.json');
const MAX_SUBSCRIPTION_BYTES = 6 * 1024 * 1024;
/**
 * How long the body of a subscription response may take to arrive.
 *
 * The dial has its own per-address bound, but that stops applying once the
 * connection is established: a server that sends headers and then stalls would
 * otherwise block the read forever, and the API queue is serial.
 */
const BODY_READ_TIMEOUT_MS = 30_000;
const MAX_REQUEST_BYTES = 16 * 1024 * 1024;

/** Node URIs pasted straight into the subscription box, one per line. */
const NODE_URI = /^(?:ss|vmess|trojan|vless|hysteria2|hy2|tuic|socks|socks5|socks5h):\/\//i;
const EGRESS_URLS = ['https://ifconfig.me/ip', 'https://api.ipify.org?format=json', 'https://ipinfo.io/ip'];
const DELAY_URL = 'https://www.gstatic.com/generate_204';

/** @type {{subscriptionUrl:string,nodes:Array<Record<string, unknown>>,selected:string,updatedAt:string|null,format:string|null,warnings:string[],userinfo:Record<string,number>|null,hosts:Record<string,string>}} */
let state = {
  subscriptionUrl: '',
  nodes: [],
  selected: '',
  updatedAt: null,
  format: null,
  warnings: [],
  userinfo: null,
  hosts: {},
  allowInsecure: false,
  directHosts: [],
};

const runtime = {
  disposed: false,
  phase: 'idle',
  connected: false,
  port: null,
  apiPort: null,
  secret: null,
  group: null,
  coreVersion: null,
  exitIp: null,
  lastError: null,
  coreHandle: null,
  coreAbort: null,
  // Aborts the geodata download when the user disconnects mid-connect.
  connectAbort: null,
  exitState: null,
  proxyDispose: null,
  generation: 0,
  stopping: false,
};

let ready = Promise.resolve();
let taskQueue = Promise.resolve();
let httpProxyPromise;
let shutdownPromise;
let hostContext;
let configuredCorePath = '';
/** Extra hosts/IPs the user wants pinned to DIRECT, from the plugin config. */
let configuredDirectHosts = [];

export const inject = ['webServer', 'connection', 'subprocess', 'tools'];

export function apply(ctx, config = {}) {
  hostContext = ctx;
  configuredCorePath = typeof config?.corePath === 'string' ? config.corePath : '';
  configuredDirectHosts = Array.isArray(config?.directHosts)
    ? config.directHosts.filter((item) => typeof item === 'string' && item.trim() !== '')
    : [];
  // A module can be re-activated after HMR without re-evaluation. Reset the
  // process-local runtime flags that a previous unload marked as disposed.
  runtime.disposed = false;
  runtime.phase = 'idle';
  runtime.connected = false;
  runtime.port = null;
  runtime.apiPort = null;
  runtime.secret = null;
  runtime.group = null;
  runtime.coreVersion = null;
  runtime.exitIp = null;
  runtime.lastError = null;
  runtime.coreHandle = null;
  runtime.coreAbort = null;
  runtime.exitState = null;
  runtime.proxyDispose = null;
  runtime.generation = 0;
  runtime.stopping = false;
  state = {
    subscriptionUrl: '',
    nodes: [],
    selected: '',
    updatedAt: null,
    format: null,
    warnings: [],
    userinfo: null,
    hosts: {},
    allowInsecure: false,
    // Every place that rebuilds `state` has to list this field, or it vanishes
    // on that reset and the next read throws "not iterable". `loadState` fills
    // it from disk a moment later; the empty array here is what keeps the shape
    // valid in between.
    directHosts: [],
  };
  shutdownPromise = undefined;
  taskQueue = Promise.resolve();
  httpProxyPromise = undefined;

  const log = (level, message) => {
    const logger = ctx.logger;
    if (logger && typeof logger[level] === 'function') logger[level](`tunnel: ${message}`);
  };

  ready = loadState().catch((error) => {
    runtime.lastError = `读取本地状态失败：${errorMessage(error)}`;
    runtime.phase = 'error';
    log('warn', runtime.lastError);
  });

  ctx.effect(
    () => ctx.webServer.register({ kind: 'exact', path: API_PATH, handler: (req, res) => handleApi(ctx, req, res) }),
    'tunnel: management API',
  );

  ctx.effect(
    () =>
      ctx.tools.register({
        name: 'tunnel_connection',
        description:
          'Inspect or control the Harness Tunnel. Use status before acting, subscribe to load a Clash or base64 subscription URL, import to load raw Clash YAML or a base64 node list, connect to route the harness through the selected node, disconnect to restore direct access, select to choose a node, and test to report the current exit IP.',
        parameters: {
          type: 'object',
          additionalProperties: false,
          properties: {
            action: {
              type: 'string',
              description: 'One of: status, subscribe, import, connect, disconnect, select, test.',
            },
            url: {
              type: 'string',
              description: 'Subscription URL for the subscribe action.',
            },
            content: {
              type: 'string',
              description: 'Raw Clash YAML or base64/plain node list for the import action.',
            },
            node: {
              type: 'string',
              description: 'Exact node name for the select action. Use status to discover names.',
            },
          },
          required: ['action'],
        },
        output: {
          schema: {
            type: 'object',
            additionalProperties: false,
            properties: {
              ok: { type: 'boolean' },
              message: { type: 'string' },
            },
            required: ['ok', 'message'],
          },
          render: (_args, value) => [{ type: 'text', text: value.message }],
        },
        timeoutMs: 180_000,
        isConcurrencySafe: (args) => args?.action === 'status' || args?.action === 'test',
        async execute(args, exec) {
          await ready;
          exec.signal.throwIfAborted();
          const action = typeof args?.action === 'string' ? args.action : '';
          if (action === 'status') return { ok: true, message: statusMessage() };
          if (action === 'subscribe') {
            if (typeof args?.url !== 'string' || args.url.trim() === '') throw new Error('subscribe 需要 url 参数');
            await enqueue(() => updateSubscription(args.url));
            return { ok: true, message: statusMessage() };
          }
          if (action === 'import') {
            if (typeof args?.content !== 'string' || args.content.trim() === '') throw new Error('import 需要 content 参数');
            await enqueue(() => importSubscription(args.content));
            return { ok: true, message: statusMessage() };
          }
          if (action === 'connect') {
            await enqueue(connectInternal);
            return { ok: true, message: statusMessage() };
          }
          if (action === 'disconnect') {
            await enqueue(disconnectInternal);
            return { ok: true, message: statusMessage() };
          }
          if (action === 'select') {
            if (typeof args?.node !== 'string' || args.node.trim() === '') throw new Error('select 需要 node 参数');
            await enqueue(() => selectNode(args.node));
            return { ok: true, message: statusMessage() };
          }
          if (action === 'test') {
            const result = await testEgress();
            return { ok: true, message: `出口 IP：${result.ip}（${result.latencyMs} ms）` };
          }
          throw new Error('action 必须是 status、subscribe、connect、disconnect、select 或 test');
        },
      }),
    'tunnel: agent tool',
  );

  ctx.effect(
    () => () => shutdown(),
    'tunnel: runtime lifecycle',
  );
}

async function loadState() {
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await chmod(DATA_DIR, 0o700).catch(() => {});
  let raw;
  try {
    raw = await readFile(STATE_PATH, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('state.json 不是有效的 JSON');
  }
  if (parsed === null || typeof parsed !== 'object') return;

  state.subscriptionUrl = typeof parsed.subscriptionUrl === 'string' ? parsed.subscriptionUrl : '';
  state.updatedAt = typeof parsed.updatedAt === 'string' ? parsed.updatedAt : null;
  state.format = typeof parsed.format === 'string' ? parsed.format : null;
  state.warnings = Array.isArray(parsed.warnings) ? parsed.warnings.filter((item) => typeof item === 'string').slice(0, 8) : [];
  state.userinfo = sanitizeUserinfo(parsed.userinfo);
  state.nodes = Array.isArray(parsed.nodes) ? parsed.nodes.filter(isStoredNode) : [];
  state.hosts = sanitizeHosts(parsed.hosts);
  state.selected = typeof parsed.selected === 'string' ? parsed.selected : '';
  state.allowInsecure = parsed.allowInsecure === true;
  state.directHosts = Array.isArray(parsed.directHosts)
    ? parsed.directHosts.filter((item) => typeof item === 'string' && item.trim() !== '').slice(0, 200)
    : [];
  if (!state.nodes.some((node) => node.name === state.selected)) state.selected = state.nodes[0]?.name ?? '';
}

async function saveState() {
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await chmod(DATA_DIR, 0o700).catch(() => {});
  const temporary = `${STATE_PATH}.${randomBytes(4).toString('hex')}.tmp`;
  const body = JSON.stringify(
    {
      version: 1,
      subscriptionUrl: state.subscriptionUrl,
      updatedAt: state.updatedAt,
      format: state.format,
      warnings: state.warnings,
      userinfo: state.userinfo,
      hosts: state.hosts,
      nodes: state.nodes,
      selected: state.selected,
      allowInsecure: state.allowInsecure,
      directHosts: Array.isArray(state.directHosts) ? state.directHosts : [],
    },
    null,
    2,
  );
  try {
    await writeFile(temporary, body, { mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => {});
    await rename(temporary, STATE_PATH);
    await chmod(STATE_PATH, 0o600).catch(() => {});
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
}

function isStoredNode(node) {
  return (
    node !== null &&
    typeof node === 'object' &&
    typeof node.name === 'string' &&
    node.name !== '' &&
    typeof node.type === 'string' &&
    typeof node.server === 'string' &&
    Number.isInteger(node.port)
  );
}

function sanitizeUserinfo(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const result = {};
  for (const key of ['upload', 'download', 'total', 'expire']) {
    if (Number.isFinite(value[key]) && value[key] >= 0) result[key] = value[key];
  }
  return Object.keys(result).length === 0 ? null : result;
}

/**
 * Accept only entries that can become a valid mihomo rule.
 *
 * Shape decides the rule type later (see userDirectRules in lib/mihomo.js), so
 * this only has to reject what is neither an address nor a hostname. Refusing
 * here rather than at config build time keeps one bad paste from making the
 * whole tunnel fail to start.
 */
/**
 * True when `value` is a hostname, an IP literal, or a CIDR block.
 *
 * The address test runs through node:net's own parser rather than a character
 * class. A character-class test accepts anything made of hex digits and dots,
 * which means "abc123" and "cafe1" pass as addresses and then reach mihomo as
 * `IP-CIDR,abc123/32` — a rule the core rejects, which takes the whole config
 * with it and leaves the user with a tunnel that will not start. Measured on
 * exactly that input before this change.
 */
function isDirectEntry(value) {
  if (value.includes('/')) {
    const [base, prefix] = value.split('/');
    // Digits only: Number('abc') is NaN but Number('') is 0, so an integer
    // check alone would accept `1.2.3.4/` as a /0 rule.
    if (!/^\d{1,3}$/.test(prefix)) return false;
    const bits = Number(prefix);
    const version = isIP(base);
    if (version === 4) return bits <= 32;
    if (version === 6) return bits <= 128;
    return false;
  }
  if (isIP(value) !== 0) return true;
  // A dotted token that is not a legal address ("999.1.1.1") is not a hostname
  // either, however much it looks like one.
  if (/^[\d.]+$/.test(value)) return false;
  return /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(value);
}

function sanitizeDirectHosts(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of value) {
    const item = typeof raw === 'string' ? raw.trim().replace(/^\./, '') : '';
    if (item === '' || seen.has(item)) continue;
    if (!isDirectEntry(item)) continue;
    seen.add(item);
    out.push(item);
    if (out.length >= 200) break;
  }
  return out;
}

function sanitizeHosts(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return {};
  const result = {};
  for (const [key, target] of Object.entries(value)) {
    if (typeof target !== 'string' || key === '' || key === '__proto__') continue;
    result[key] = target;
  }
  return result;
}

function publicState() {
  return {
    phase: runtime.phase,
    connected: runtime.connected,
    port: runtime.port,
    coreVersion: runtime.coreVersion,
    exitIp: runtime.exitIp,
    lastError: runtime.lastError,
    group: runtime.group,
    coreAvailable: existsSync(resolveCorePath(configuredCorePath)),
    // Whether the split-rule databases are on disk. The first connect has to
    // fetch them, which takes tens of seconds; the UI says so instead of
    // showing an unexplained wait on `preparing`.
    geodataReady: geodataStatus(),
    subscription: {
      url: maskSubscriptionUrl(state.subscriptionUrl),
      hasSubscription: state.subscriptionUrl !== '',
      updatedAt: state.updatedAt,
      format: state.format,
      warnings: state.warnings,
      userinfo: state.userinfo,
      nodeCount: state.nodes.length,
      allowInsecure: state.allowInsecure,
    },
    nodes: state.nodes.map((node) => ({ name: node.name, type: node.type, insecure: node.insecure === true })),
    selected: state.selected,
    directHosts: Array.isArray(state.directHosts) ? state.directHosts : [],
  };
}

function statusMessage() {
  const location = state.selected ? `，当前节点 ${state.selected}` : '';
  const preview = state.nodes.slice(0, 12).map((node) => node.name).join('、');
  const more = state.nodes.length > 12 ? ` 等 ${state.nodes.length} 个` : '';
  const inventory = preview === '' ? '' : `；节点：${preview}${more}`;
  if (runtime.connected) {
    const exit = runtime.exitIp ? `，出口 IP ${runtime.exitIp}` : '';
    return `已连接${location}（本地端口 ${runtime.port}${exit}）${inventory}`;
  }
  if (runtime.phase === 'error' && runtime.lastError) return `未连接：${runtime.lastError}${inventory}`;
  return state.nodes.length > 0
    ? `未连接；已保存 ${state.nodes.length} 个节点${location}${inventory}`
    : '未连接；尚未配置订阅';
}

async function handleApi(ctx, req, res) {
  try {
    let rejection;
    try {
      rejection = ctx.connection.requestRejection(req);
    } catch {
      rejection = 403;
    }
    if (rejection !== undefined) {
      res.statusCode = rejection;
      res.end();
      return;
    }
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.setHeader('allow', 'POST');
      res.end();
      return;
    }
    const mediaType = String(req.headers['content-type'] ?? '')
      .split(';', 1)[0]
      .trim()
      .toLowerCase();
    if (mediaType !== 'application/json') {
      sendJson(res, 415, { ok: false, error: { code: 'unsupported-media-type', message: '请求必须使用 application/json' } });
      return;
    }

    const raw = await readBody(req, MAX_REQUEST_BYTES);
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      sendJson(res, 400, { ok: false, error: { code: 'bad-json', message: '请求体不是有效的 JSON' } });
      return;
    }
    if (message === null || typeof message !== 'object' || typeof message.action !== 'string') {
      sendJson(res, 400, { ok: false, error: { code: 'bad-request', message: '缺少 action' } });
      return;
    }

    await ready;
    const result = await dispatch(message.action, message);
    sendJson(res, 200, { ok: true, ...result });
  } catch (error) {
    if (!res.headersSent) {
      sendJson(res, 200, {
        ok: false,
        error: { code: error?.code ?? 'tunnel-error', message: errorMessage(error) },
      });
    }
  }
}

async function dispatch(action, message) {
  if (action === 'state') return { state: publicState() };
  if (action === 'subscribe') {
    await enqueue(() => updateSubscription(String(message.url ?? '')));
    return { state: publicState() };
  }
  if (action === 'import') {
    await enqueue(() => importSubscription(String(message.content ?? '')));
    return { state: publicState() };
  }
  if (action === 'clear') {
    await enqueue(clearSubscription);
    return { state: publicState() };
  }
  if (action === 'connect') {
    await enqueue(connectInternal);
    return { state: publicState() };
  }
  if (action === 'disconnect') {
    await enqueue(disconnectInternal);
    return { state: publicState() };
  }
  if (action === 'select') {
    await enqueue(() => selectNode(String(message.name ?? '')));
    return { state: publicState() };
  }
  if (action === 'latency') {
    const result = await measureLatency(typeof message.name === 'string' ? message.name : '');
    return { ...result, state: publicState() };
  }
  if (action === 'test') {
    const result = await testEgress();
    return { ...result, state: publicState() };
  }
  if (action === 'setDirectHosts') {
    await enqueue(async () => {
      const previous = Array.isArray(state.directHosts) ? state.directHosts : [];
      const next = sanitizeDirectHosts(message.directHosts);
      if (next.join('\n') !== previous.join('\n')) {
        state.directHosts = next;
        await saveState();
      }
    });
    return { state: publicState() };
  }
  if (action === 'setAllowInsecure') {
    await enqueue(async () => {
      const next = message.allowInsecure === true;
      if (next !== state.allowInsecure) {
        state.allowInsecure = next;
        // 重新应用过滤：关闭开关时立即过滤掉 insecure 节点。
        if (next === false) {
          const insecureCount = state.nodes.filter((node) => node.insecure === true).length;
          if (insecureCount > 0) {
            state.nodes = state.nodes.filter((node) => node.insecure !== true);
            if (!state.nodes.some((node) => node.name === state.selected)) state.selected = state.nodes[0]?.name ?? '';
            state.warnings.push(`已按安全策略过滤 ${insecureCount} 个关闭证书校验的节点`);
            state.warnings = state.warnings.slice(0, 8);
          }
        }
        await saveState();
      }
    });
    return { state: publicState() };
  }
  throw new Error(`未知操作：${action}`);
}

function enqueue(task) {
  const run = taskQueue.then(task, task);
  taskQueue = run.catch(() => {});
  return run;
}

/**
 * 手动处理重定向并逐跳校验，禁止跟随重定向进入内网地址。
 *
 * 每一跳都用 `pinnedFetchAny` 连到**刚校验过的那些地址**：普通 `fetch` 会自己
 * 再解析一次域名，那正是 DNS rebinding 的窗口。重定向仍由这里手工处理
 * （`redirect: 'manual'` 的语义），下一跳的地址同样先校验再连接。
 *
 * 跳数上限、协议白名单、降级拒绝与环路检测都在 `lib/redirect-policy.js`，
 * 那里可以脱离网络测试；这里只负责把策略串起来。
 *
 * 返回一个 `{ status, headers, body }` 形状的对象，与 `fetch` 的消费方式一致。
 */
async function fetchSubscription(initialUrl) {
  let current = initialUrl;
  const visited = new Set([normalizeForVisit(initialUrl)]);
  for (let hop = 0; ; hop += 1) {
    const target = await assertSafeTarget(current);
    // 同一域名可能返回多条地址，只有部分可达（常见：IPv6 无路由）。回退是安全的
    // —— 列表里每一条都已通过守卫，不是「重试到能用为止」。
    const response = await pinnedFetchAny(current, target.addresses, {
      headers: {
        'user-agent': 'clash.meta/1.19.33',
        accept: 'text/yaml,text/plain,application/yaml,*/*',
      },
      signal: AbortSignal.timeout(30_000),
    });
    const status = response.statusCode ?? 0;
    if (status >= 300 && status < 400) {
      // Drain the redirect body so the socket is released before the next hop.
      response.resume();
      const decision = resolveRedirect(current, response.headers.location, visited, hop);
      if (decision.action === 'stop') {
        if (decision.reason === 'too-many-hops') throw new Error('订阅地址重定向次数过多');
        if (decision.reason === 'redirect-loop') throw new Error('订阅地址重定向出现环路');
        if (decision.reason === 'downgrade-refused') {
          throw new Error('订阅地址从 HTTPS 重定向到 HTTP，已拒绝（会丢失传输加密）');
        }
        if (decision.reason.startsWith('protocol-not-allowed')) {
          throw new Error('订阅地址重定向到了不受支持的协议');
        }
        // 重定向本身有问题时给出自己的诊断。返回 body:null 会让上层报
        // 「订阅地址没有返回内容」，那是在说另一件事，会误导排障。
        if (decision.reason === 'missing-location') {
          throw new Error(`订阅地址返回了重定向（HTTP ${status}）但没有 Location 头`);
        }
        if (decision.reason === 'invalid-location') {
          throw new Error(`订阅地址返回了无法解析的重定向地址（HTTP ${status}）`);
        }
        throw new Error(`订阅地址重定向失败（HTTP ${status}）`);
      }
      current = decision.url;
      continue;
    }
    return { status, headers: response.headers, body: response };
  }
}

/** 脱敏订阅 URL，避免把内嵌令牌/密码暴露给前端。 */
function maskSubscriptionUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') return '';
  try {
    const parsed = new URL(rawUrl);
    parsed.search = parsed.search === '' ? '' : '?***';
    parsed.hash = parsed.hash === '' ? '' : '#***';
    parsed.username = parsed.username === '' ? '' : '***';
    parsed.password = parsed.password === '' ? '' : '***';
    return parsed.toString();
  } catch {
    return '';
  }
}

async function updateSubscription(rawUrl) {
  if (runtime.connected) throw new Error('请先断开连接，再更新订阅');
  const url = rawUrl.trim();
  if (url === '') throw new Error('请输入订阅链接');
  if (url.length > 4096) throw new Error('订阅链接过长');
  // A node URI (vless://, ss://, …) is a single proxy, not a fetchable URL.
  // Route it through the local parser so pasting a share link just works.
  if (NODE_URI.test(url)) return importSubscription(url);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('订阅链接不是有效的 URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('订阅链接必须使用 http 或 https');
  }
  // 地址校验交给 fetchSubscription 的逐跳守卫：这里再查一次只会让同一个域名
  // 被解析两遍，而且它拿到的地址并不会被用于连接（真正钉住的是循环里那次）。

  let response;
  try {
    response = await fetchSubscription(parsed);
  } catch (error) {
    throw new Error(`获取订阅失败：${errorMessage(error).split(url).join('<订阅链接>')}`);
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`订阅地址返回 HTTP ${response.status}`);
  }
  if (response.body === null) throw new Error('订阅地址没有返回内容');
  const body = await readCapped(response.body, MAX_SUBSCRIPTION_BYTES, '订阅内容');
  if (body.trim().startsWith('<')) throw new Error('订阅地址返回了网页而不是节点配置，请检查链接是否需要 Clash UA 或已过期');

  let result;
  try {
    result = parseSubscription(body);
  } catch (error) {
    throw new Error(errorMessage(error));
  }

  return applySubscription(result, {
    url,
    // `fetchSubscription` returns Node's plain header object (lower-cased keys),
    // not a WHATWG `Headers` — so there is no `.get()` here. Reading it by key is
    // the only correct form; calling `.get()` threw on every successful update.
    userinfo: parseUserinfo(response.headers['subscription-userinfo']) ?? state.userinfo,
  });
}

/**
 * Import a raw Clash YAML document (or base64/plain URI list) from the UI. It
 * has no URL to update from, so the stored URL is cleared and the cached nodes
 * become the source of truth.
 */
async function importSubscription(rawContent) {
  if (runtime.connected) throw new Error('请先断开连接，再导入配置');
  const content = String(rawContent ?? '');
  if (content.trim() === '') throw new Error('请粘贴 Clash YAML 或节点列表');
  if (Buffer.byteLength(content, 'utf8') > MAX_SUBSCRIPTION_BYTES) {
    throw new Error(`配置内容超过 ${Math.round(MAX_SUBSCRIPTION_BYTES / 1024 / 1024)} MB`);
  }
  if (content.trim().startsWith('<')) throw new Error('内容看起来是网页而不是 YAML 配置');

  let result;
  try {
    result = parseSubscription(content);
  } catch (error) {
    throw new Error(errorMessage(error));
  }
  return applySubscription(result, { url: '', userinfo: null });
}

async function applySubscription(result, options) {
  state.subscriptionUrl = options.url;
  state.nodes = result.nodes;
  state.hosts = result.hosts ?? {};
  state.format = result.format;
  state.warnings = [...(result.warnings ?? [])];
  state.updatedAt = new Date().toISOString();
  state.userinfo = options.userinfo ?? null;
  // 默认拒绝 skip-cert-verify 节点（关闭证书校验，存在中间人风险）。
  // 仅当用户显式开启 allowInsecure 时才保留这类节点。
  if (state.allowInsecure !== true) {
    const insecureCount = state.nodes.filter((node) => node.insecure === true).length;
    if (insecureCount > 0) {
      state.nodes = state.nodes.filter((node) => node.insecure !== true);
      state.warnings.push(`已按安全策略过滤 ${insecureCount} 个关闭证书校验的节点，如需使用请在设置中开启「允许不安全节点」`);
      state.warnings = state.warnings.slice(0, 8);
    }
  }
  if (!state.nodes.some((node) => node.name === state.selected)) state.selected = state.nodes[0]?.name ?? '';
  runtime.lastError = null;
  await saveState();
  return publicState();
}

async function clearSubscription() {
  if (runtime.connected) throw new Error('请先断开连接，再删除订阅');
  state = {
    subscriptionUrl: '',
    nodes: [],
    selected: '',
    updatedAt: null,
    format: null,
    warnings: [],
    userinfo: null,
    hosts: {},
    allowInsecure: false,
    // Removing a subscription clears what came with it, but the direct list is
    // the user's own setting and is not part of the subscription — it survives.
    directHosts: Array.isArray(state.directHosts) ? state.directHosts : [],
  };
  runtime.lastError = null;
  await removeConfig();
  await saveState();
  return publicState();
}

async function connectInternal() {
  if (runtime.disposed) throw new Error('插件已卸载');
  if (runtime.connected) return publicState();
  if (runtime.proxyDispose !== null || runtime.coreHandle !== null) await teardownRuntime();

  runtime.lastError = null;
  runtime.connectAbort = new AbortController();
  setPhase('preparing');
  try {
    if (state.nodes.length === 0) {
      if (state.subscriptionUrl === '') throw new Error('请先在设置中填写订阅链接');
      await updateSubscription(state.subscriptionUrl);
    }
    if (state.nodes.length === 0) throw new Error('订阅中没有可用节点');

    const corePath = await ensureCore(configuredCorePath, () => setPhase('downloading'));
    if (runtime.disposed) throw new Error('插件已卸载');

    // The China-direct rules reference GeoSite.dat and GeoIP.dat. A rule whose
    // database is missing stops the core from starting at all, so the databases
    // are provisioned first and the rules are dropped when that fails: a working
    // tunnel without split routing beats no tunnel.
    const missingGeodata = await ensureGeodata({
      log: (message) => {
        const logger = hostContext?.logger;
        if (logger && typeof logger.info === 'function') logger.info('tunnel: ' + message);
      },
      signal: runtime.connectAbort?.signal,
    });
    if (runtime.disposed) throw new Error('插件已卸载');
    const cnDirect = missingGeodata.length === 0;
    if (!cnDirect) {
      // Say it in three places, because each reaches a different reader: the
      // log for whoever debugs it, the connection error line for whoever just
      // clicked Connect, and `warnings` for the settings page that shows the
      // subscription state.
      //
      // The failure being reported here is subtle by nature — the tunnel
      // connects fine, it is only the split routing that silently did not turn
      // on — so "connected successfully" with no explanation is exactly the
      // wrong message.
      const detail = missingGeodata.join('、');
      const logger = hostContext?.logger;
      if (logger && typeof logger.warn === 'function') {
        logger.warn(`tunnel: 分流规则数据库不可用（${detail}），已回退为全局代理`);
      }
      state.warnings = [
        `分流规则数据库不可用（${detail}），本次连接已回退为全局代理：所有流量仍走所选节点，国内站点不会直连。`,
        ...state.warnings,
      ].slice(0, 8);
      runtime.lastError = `分流未生效：缺少 ${detail}，已回退为全局代理`;
    }

    const { mixedPort, apiPort } = await allocatePorts();
    const secret = randomBytes(24).toString('hex');
    const { hosts, pinned } = await resolveProxyServers(state.nodes, state.hosts);
    if (runtime.disposed) throw new Error('插件已卸载');
    const { text, group } = buildConfig(state.nodes, {
      mixedPort,
      apiPort,
      secret,
      hosts,
      cnDirect,
      // The config file is for a fixed list the deployment owns; the UI list is
      // what the person in front of it just typed. Both are honoured, config
      // first so a value pinned by the deployment is never silently dropped.
      directHosts: [...configuredDirectHosts, ...(Array.isArray(state.directHosts) ? state.directHosts : [])],
    });
    await writeConfig(text);
    const pinNote = describePinned(pinned);
    if (pinNote !== '') {
      const logger = hostContext?.logger;
      if (logger && typeof logger.info === 'function') logger.info('tunnel: ' + pinNote);
    }

    const abort = new AbortController();
    const exitState = { exited: false, detail: '' };
    const generation = ++runtime.generation;
    runtime.stopping = false;
    setPhase('starting');

    const handle = hostContext.subprocess.spawn({
      argv: [corePath, '-d', DATA_DIR, '-f', path.join(DATA_DIR, 'config.yaml')],
      cwd: DATA_DIR,
      env: { HOME: DATA_DIR, TMPDIR: DATA_DIR },
      stdio: {
        stdin: 'ignore',
        stdout: { maxBytes: 256 * 1024 },
        stderr: { maxBytes: 256 * 1024 },
      },
      graceMs: 2_000,
      signal: abort.signal,
    });

    runtime.coreHandle = handle;
    runtime.coreAbort = abort;
    runtime.exitState = exitState;
    runtime.port = mixedPort;
    runtime.apiPort = apiPort;
    runtime.secret = secret;
    runtime.group = group;
    runtime.coreVersion = null;

    handle.done
      .then(async (outcome) => {
        const detail = await readCoreLog(handle);
        exitState.exited = true;
        exitState.detail = detail || `退出码 ${outcome.exitCode ?? outcome.signal ?? 'unknown'}`;
        if (generation !== runtime.generation || runtime.stopping) return;
        await failFromCoreExit(generation, exitState.detail);
      })
      .catch(async (error) => {
        exitState.exited = true;
        exitState.detail = errorMessage(error);
        if (generation !== runtime.generation || runtime.stopping) return;
        await failFromCoreExit(generation, exitState.detail);
      });

    const version = await waitForCore(apiPort, secret, exitState);
    if (runtime.disposed) throw new Error('插件已卸载');
    runtime.coreVersion = typeof version.version === 'string' ? version.version : CORE_VERSION;
    const groupInfo = await waitForGroup(apiPort, secret, group, exitState);
    if (groupInfo === null || typeof groupInfo !== 'object') throw new Error('mihomo 没有创建代理组');
    if (state.selected !== '') {
      await selectOnCore(group, state.selected);
    }
    await installProxy(mixedPort);
    if (runtime.disposed) throw new Error('插件已卸载');
    runtime.connected = true;
    runtime.exitIp = null;
    setPhase('connected');
    return publicState();
  } catch (error) {
    const message = errorMessage(error);
    await teardownRuntime();
    runtime.lastError = message;
    setPhase('error');
    throw error;
  }
}

/**
 * Extend the stored host overrides with a pinned address for every proxy server
 * that resolves to IPv6 only.
 */
async function resolveProxyServers(nodes, storedHosts) {
  const base = storedHosts !== null && typeof storedHosts === 'object' ? storedHosts : {};
  try {
    return await pinIpv6OnlyServers(nodes, base);
  } catch (error) {
    // Resolution is best-effort: a failure here must never block connecting.
    // Still surface it so a regression in the resolver is not silently lost.
    const logger = hostContext?.logger;
    if (logger && typeof logger.warn === 'function') {
      logger.warn('tunnel: 节点 IPv6 解析降级，继续连接：' + errorMessage(error));
    }
    return { hosts: { ...base }, pinned: [] };
  }
}

async function disconnectInternal() {
  setPhase('stopping');
  await teardownRuntime();
  runtime.lastError = null;
  runtime.exitIp = null;
  setPhase('idle');
  return publicState();
}

async function teardownRuntime() {
  runtime.stopping = true;
  runtime.generation += 1;
  // A disconnect mid-connect must stop the geodata download in its tracks; the
  // fetch aborts and ensureGeodata returns its missing list immediately.
  if (runtime.connectAbort !== null) {
    runtime.connectAbort.abort();
    runtime.connectAbort = null;
  }
  const proxyDispose = runtime.proxyDispose;
  runtime.proxyDispose = null;
  if (proxyDispose !== null) {
    try {
      await proxyDispose();
    } catch {
      // Restoring the previous dispatcher is best effort during teardown.
    }
  }

  const handle = runtime.coreHandle;
  const abort = runtime.coreAbort;
  runtime.coreHandle = null;
  runtime.coreAbort = null;
  runtime.exitState = null;
  runtime.connected = false;
  runtime.port = null;
  runtime.apiPort = null;
  runtime.secret = null;
  runtime.group = null;
  runtime.coreVersion = null;

  if (abort !== null) abort.abort();
  if (handle !== null) {
    try {
      handle.terminate();
    } catch {
      // The process may already have exited.
    }
    await withTimeout(handle.waitForExit(), 4_000);
  }
  await removeConfig();
}

async function failFromCoreExit(generation, detail) {
  if (generation !== runtime.generation || runtime.stopping) return;
  runtime.stopping = true;
  runtime.generation += 1;
  const proxyDispose = runtime.proxyDispose;
  runtime.proxyDispose = null;
  if (proxyDispose !== null) {
    try {
      await proxyDispose();
    } catch {
      // The previous dispatcher is still usable even if cleanup reports an error.
    }
  }
  runtime.connected = false;
  runtime.port = null;
  runtime.apiPort = null;
  runtime.secret = null;
  runtime.group = null;
  runtime.coreVersion = null;
  runtime.coreHandle = null;
  runtime.coreAbort = null;
  runtime.exitState = null;
  await removeConfig();
  runtime.lastError = `mihomo 已退出：${detail}`;
  setPhase('error');
}

async function selectNode(name) {
  const node = state.nodes.find((candidate) => candidate.name === name);
  if (node === undefined) throw new Error('节点不存在，请刷新订阅');
  if (runtime.connected && runtime.group !== null) {
    await selectOnCore(runtime.group, name);
  }
  state.selected = name;
  await saveState();
  return publicState();
}

async function selectOnCore(group, name) {
  if (runtime.apiPort === null || runtime.secret === null) throw new Error('内核尚未就绪');
  await coreFetch(runtime.apiPort, runtime.secret, `/proxies/${encodeURIComponent(group)}`, {
    method: 'PUT',
    body: JSON.stringify({ name }),
    signal: AbortSignal.timeout(5_000),
  });
}

async function measureLatency(name) {
  if (!runtime.connected || runtime.apiPort === null || runtime.secret === null) {
    throw new Error('请先连接后再测速');
  }
  if (name.trim() !== '') {
    const delay = await delayFor(name.trim());
    return { results: { [name.trim()]: delay } };
  }
  const names = state.nodes.map((node) => node.name).slice(0, 80);
  const results = {};
  let cursor = 0;
  const workers = Array.from({ length: 4 }, async () => {
    while (cursor < names.length) {
      const current = names[cursor++];
      try {
        results[current] = await delayFor(current);
      } catch {
        results[current] = null;
      }
    }
  });
  await Promise.all(workers);
  return { results, tested: names.length, total: state.nodes.length };
}

async function delayFor(name) {
  const params = new URLSearchParams({ timeout: '3000', url: DELAY_URL });
  const info = await coreFetch(runtime.apiPort, runtime.secret, `/proxies/${encodeURIComponent(name)}/delay?${params.toString()}`, {
    signal: AbortSignal.timeout(6_000),
  });
  return info !== null && typeof info === 'object' && Number.isFinite(info.delay) ? info.delay : null;
}

async function testEgress() {
  if (!runtime.connected) throw new Error('请先连接后再测试出口');
  const started = Date.now();
  let lastError = '';
  for (const url of EGRESS_URLS) {
    try {
      const response = await fetch(url, {
        headers: { 'user-agent': 'dsh-tunnel/1.0', accept: 'application/json,text/plain' },
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
        continue;
      }
      const text = (await response.text()).trim();
      let ip = text.slice(0, 80);
      if (text.startsWith('{')) {
        try {
          const data = JSON.parse(text);
          if (data !== null && typeof data === 'object' && typeof data.ip === 'string') ip = data.ip;
        } catch {
          // Keep the raw text as a best-effort answer.
        }
      }
      if (ip === '') {
        lastError = 'empty response';
        continue;
      }
      runtime.exitIp = ip;
      return { ip, latencyMs: Date.now() - started, state: publicState() };
    } catch (error) {
      lastError = errorMessage(error);
    }
  }
  throw new Error(`出口测试失败：${lastError || '没有可用的出口检测服务'}`);
}

/**
 * Hosts that must never enter the tunnel, whatever the rule set says.
 *
 * A rule of DIRECT inside mihomo still routes the connection through the core:
 * the request is accepted on the loopback port, the core dials the target
 * itself. That is fine for latency, but it hands every such request to a
 * process that is also carrying traffic from a foreign exit node — and at least
 * one local service rejects requests that arrive through it (the WorkBuddy
 * bridge returns 502 transport failures only while the tunnel is connected,
 * even though the same URLs answer normally when fetched directly).
 *
 * NO_PROXY is the only mechanism that keeps a request out of the core
 * entirely, so the domestic services that matter are listed here and are
 * fetched by the host process itself.
 *
 * Values from the environment are appended rather than replaced: a deployment
 * that already pins its own bypass list keeps it.
 */
const DEFAULT_NO_PROXY = [
  'localhost',
  '127.0.0.1',
  '::1',
  // WorkBuddy bridge upstreams (Tencent). Domestic, and currently unhappy when
  // reached through the core — see the comment above.
  //
  // These are exact hostnames, not wildcard suffixes. A leading dot in NO_PROXY
  // matches the whole domain (".tencent.com" would bypass every Tencent host,
  // including ones the user may actually want on the tunnel). The bridge only
  // talks to these three hosts, so naming them exactly keeps the bypass tight.
  'copilot.tencent.com',
  'www.codebuddy.cn',
  'www.workbuddy.ai',
];

async function installProxy(port) {
  const module = await loadHttpProxy();
  const existingNoProxy = process.env.NO_PROXY || process.env.no_proxy || '';
  const values = new Map([
    ['http_proxy', `http://127.0.0.1:${port}`],
    ['https_proxy', `http://127.0.0.1:${port}`],
  ]);
  // Always set no_proxy: leaving the core in the path for the hosts above is
  // what breaks them. An environment value is unioned in, not substituted.
  const bypass = existingNoProxy === ''
    ? DEFAULT_NO_PROXY
    : [...DEFAULT_NO_PROXY, ...existingNoProxy.split(',').map((item) => item.trim()).filter(Boolean)];
  values.set('no_proxy', bypass.join(','));
  const env = {
    get(name) {
      const value = values.get(name);
      return value === undefined ? undefined : { value };
    },
  };
  runtime.proxyDispose = await module.installProxyFromEnvironment(env, (message) => {
    const logger = hostContext?.logger;
    if (logger && typeof logger.warn === 'function') logger.warn(`tunnel: ${message}`);
  });
}

async function loadHttpProxy() {
  if (httpProxyPromise !== undefined) return httpProxyPromise;
  httpProxyPromise = (async () => {
    const candidates = [];
    const entry = process.argv[1];
    if (typeof entry === 'string' && entry !== '') {
      const root = path.resolve(path.dirname(entry), '..');
      candidates.push(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-http-proxy', 'lib', 'index.js'));
      try {
        candidates.push(createRequire(entry).resolve('@deepseek-ai/dsh-http-proxy'));
      } catch {
        // The global installation layout differs; try the remaining candidates.
      }
    }
    try {
      candidates.push(fileURLToPath(import.meta.resolve('@deepseek-ai/dsh-http-proxy')));
    } catch {
      // Not installed as a direct dependency of this bundle.
    }

    const seen = new Set();
    for (const candidate of candidates) {
      if (seen.has(candidate) || !existsSync(candidate)) continue;
      seen.add(candidate);
      try {
        const module = await import(pathToFileURL(candidate).href);
        if (typeof module.installProxyFromEnvironment === 'function') return module;
      } catch {
        // Try the next candidate.
      }
    }
    throw new Error('无法加载 DSH 的 http-proxy 模块，外网路由未启用');
  })().catch((error) => {
    httpProxyPromise = undefined;
    throw error;
  });
  return httpProxyPromise;
}

async function shutdown() {
  if (shutdownPromise !== undefined) return shutdownPromise;
  shutdownPromise = (async () => {
    runtime.disposed = true;
    await teardownRuntime();
  })();
  return shutdownPromise;
}

function setPhase(phase) {
  runtime.phase = phase;
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(payload));
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.byteLength;
      if (size > maxBytes) {
        fail(new Error('请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', fail);
  });
}

/**
 * Read a response body with a hard byte cap.
 *
 * Takes the `IncomingMessage` a pinned request produced (a Node readable, not a
 * WHATWG `Response`), so it reads via `for await` and destroys the socket as soon
 * as the cap is crossed — leaving the rest of an oversized body on the wire would
 * keep the connection alive for no reason.
 */
async function readCapped(stream, maxBytes, label, timeoutMs = BODY_READ_TIMEOUT_MS) {
  const length = Number(stream.headers['content-length'] ?? '');
  if (Number.isFinite(length) && length > maxBytes) throw new Error(`${label}超过 ${Math.round(maxBytes / 1024 / 1024)} MB`);
  const chunks = [];
  let size = 0;
  // A server can send headers and then stall, which leaves `for await` blocked
  // forever. The API queue is serial, so one stalled read wedges every later
  // operation until the host restarts — the deadline has to be enforced here,
  // around the read itself, not around the dial.
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    stream.destroy();
  }, timeoutMs);
  timer.unref?.();
  try {
    for await (const value of stream) {
      size += value.byteLength;
      if (size > maxBytes) {
        stream.destroy();
        throw new Error(`${label}超过 ${Math.round(maxBytes / 1024 / 1024)} MB`);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (timedOut) throw new Error(`${label}读取超时（${Math.round(timeoutMs / 1000)} 秒未收到完整内容）`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
  if (timedOut) throw new Error(`${label}读取超时（${Math.round(timeoutMs / 1000)} 秒未收到完整内容）`);
  const contentType = String(stream.headers['content-type'] ?? '');
  const charset = /charset\s*=\s*"?([^";\s]+)/i.exec(contentType)?.[1] ?? 'utf-8';
  let decoder;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    decoder = new TextDecoder();
  }
  return decoder.decode(Buffer.concat(chunks));
}

/** Resolve after `ms` at the latest, so a stuck teardown cannot block shutdown. */
function withTimeout(promise, ms) {
  let timer = null;
  const expiry = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), ms);
  });
  return Promise.race([Promise.resolve(promise).catch(() => null), expiry]).finally(() => {
    if (timer !== null) clearTimeout(timer);
  });
}

function errorMessage(error) {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause instanceof Error ? `: ${error.cause.message}` : '';
  return `${message}${cause}`;
}
