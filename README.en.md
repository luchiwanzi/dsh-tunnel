# DSH Tunnel · Outbound Network

**A controllable outbound network for DeepSeek Harness: model requests, web tools and MCP traffic go through the proxy node you pick, while domestic traffic stays direct.**

[![npm](https://img.shields.io/npm/v/@wanziya/dsh-tunnel?label=npm&color=blue)](https://www.npmjs.com/package/@wanziya/dsh-tunnel) [![CI](https://github.com/luchiwanzi/dsh-tunnel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/luchiwanzi/dsh-tunnel/actions/workflows/ci.yml) ![platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-0078D6) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Your [**Star ⭐ ↗**](https://github.com/luchiwanzi/dsh-tunnel) keeps me motivated to update this project. Please, it means a lot to me! Found a problem or have a wish? [**Open an Issue ↗**](https://github.com/luchiwanzi/dsh-tunnel/issues/new) — **you make the wish, I'll work on it!**

**语言 / Language:** [简体中文](README.md) · English

[Releases](https://github.com/luchiwanzi/dsh-tunnel/releases) · [npm](https://www.npmjs.com/package/@wanziya/dsh-tunnel) · [Issues](https://github.com/luchiwanzi/dsh-tunnel/issues)

---

Model requests are issued by the **DSH process**, not by the browser. So "the page loads" does not mean the model API is reachable, and "the browser can open foreign sites" does not mean DSH can reach them either — especially when deployed on a mainland-China cloud server, where restricted egress is the norm. This plugin puts that problem inside the DSH settings page: no system proxy changes, no routing table edits, and no need to wrap the whole machine in a global proxy.

Works for both desktop and cloud-server deployments. The typical flow is **import a subscription or paste YAML → pick a node → connect → test the exit IP**.

## What problem does it solve?

| Common pain point | What this plugin provides |
|---|---|
| DSH is deployed fine, but calls to foreign model APIs (OpenAI, Anthropic, …) fail or time out | Configures a proxy egress for DSH model requests, fixing reachability. |
| Your local machine can reach foreign services, but DSH on the server still cannot | The proxy applies to the DSH process itself, not just the browser. |
| You don't want to change machine-wide network settings and affect other apps | Only DSH and the subprocesses it later spawns get the proxy. No system proxy, firewall or routing table changes. |
| You cannot even reach the subscription URL to fetch nodes | Paste Clash / mihomo YAML or a node list directly and parse it locally. |
| The model works, but web search / page fetching tools are still blocked | DSH process-level proxy policy covers `web_search` / `web_fetch`, MCP, and other requests that honour that policy. |
| A global proxy sends domestic services abroad too — slower, sometimes broken | Domestic-direct split routing: domestic traffic skips the node, only the rest goes through it. A direct list covers the gaps. |

> **Scope limits: this plugin solves network connectivity only. It does not provide model accounts, API keys, subscription quota, or proxy nodes.** You supply working nodes and the corresponding model credentials. Actual availability depends on node quality, the provider's supported regions, account permissions and terms of service — not every foreign model can be guaranteed to work.
>
> This plugin is not a system-level proxy or TUN tool. It does not modify system network configuration, and it does not automatically proxy login/authorization pages in your local browser. Please comply with applicable local laws and the relevant terms of service.

## Bundled components

1 total · 1 running

| Component | Description | Status |
|---|---|---|
| `dsh-tunnel` | The plugin itself: subscription parsing, node management, local mihomo core orchestration, and process-level proxy injection | ● Running |
| `mihomo` (embedded core) | [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) v1.19.33, distributed per-platform via npm packages, SHA256-verified before launch | ● Starts with the plugin |

## Installation

### Option 1: Official plugin marketplace (easiest)

In the target DSH app, open **Settings → Plugin Marketplace** (or **Plugin Management → Add Plugin**) and search for:

```text
@wanziya/dsh-tunnel
```

Just type the npm package name above into the "Add plugin" box and keep the source on the **official npm registry**.

After installing, refresh the DSH page and use it under **Settings → Outbound Network**. If it does not appear, restart DSH.

### Option 2: Command line

**Install from npm (recommended, version-pinned)**

```bash
dsh plugin --profile <profile> add @wanziya/dsh-tunnel
```

**Install from GitHub (tracks the main branch, always latest)**

Requires Git:

```bash
dsh plugin --profile <profile> add 'git+https://github.com/luchiwanzi/dsh-tunnel.git'
```

Replace `<profile>` with the profile you actually use: `desktop` by default for the desktop app, `web` for the CLI. If unsure, check the directory names under `~/.dsh/profiles/`.

> Difference between the two sources: the npm package's `latest` only advances when you publish a new version, so it can be pinned and rolled back; the GitHub method takes the newest commit on `main`, so a push takes effect immediately — good for tracking development. Both are identical after a release.

### Uninstall

```bash
dsh plugin --profile <profile> remove @wanziya/dsh-tunnel
```

If installed from GitHub, uninstall with:

```bash
dsh plugin --profile <profile> remove dsh-tunnel
```

Disconnect first. If you want to keep your subscription configuration, back up the runtime data beforehand.

## Features

- **Subscription import**: Clash / mihomo YAML subscriptions, Base64-encoded or plaintext node-link lists, and v2rayN single-node links (`vless://`, `vmess://`, `ss://`, `trojan://`, …).
- **Node switching**: Pick a node and connect or disconnect from the settings page.
- **Exit check**: Verify the current public egress IP.
- **DSH-scoped proxying**: After connecting, applies a DSH process-level HTTP proxy policy used by model requests, `web_search` / `web_fetch`, MCP, and subprocesses spawned later.
- **Local-only listener**: The HTTP/SOCKS mixed proxy binds only to `127.0.0.1` on a random port; the management API reuses the existing DSH web service.
- **IPv6-only node support**: Before connecting, each proxy server's hostname is resolved; nodes that resolve to an IPv6 address only are pinned into `hosts` so IPv6-only nodes (AAAA record only) can still connect. Nodes with an IPv4 answer, or that fail to resolve, keep their normal resolution path — connection is never blocked.
- **Domestic-direct split routing**: Traffic matching `GEOSITE,cn` and `GEOIP,CN` goes direct; only the rest uses the selected node. The rule databases (`GeoSite.dat` / `GeoIP.dat`, ~27 MB) are downloaded and SHA256-verified on first connect; `DSH_TUNNEL_GEODATA_DIR` can point at a local directory for offline use. If the databases are unavailable it falls back to a global proxy and says so clearly in the settings page.
- **Direct list**: When domestic split routing misses a site, add domains, IPs or CIDR blocks to go direct from the settings page.
- **Agent tool**: Provides `tunnel_connection` to query status, import a subscription, connect, disconnect, switch nodes and test the exit.

## Usage

1. Open **Settings → Outbound Network** at the bottom of the sidebar.
2. Paste a subscription URL and click **Save & parse**.
3. Pick a node and click **Connect**.
4. Click **Test exit** to check the public IP.
5. Click **Disconnect** when you no longer need the proxy — this restores direct access and removes the proxy environment settings for later subprocesses.

After installing this plugin in a different DSH installation you must re-enter your subscription; the repository contains no personal subscriptions, node credentials or runtime configuration.

### Domestic-direct split routing and the direct list

Domestic-direct routing is on by default after connecting: traffic matching `GEOSITE,cn` and `GEOIP,CN` skips the node, and the rest still uses the selected node. Domestic services are not detoured and do not consume subscription traffic.

The first connection downloads the rule databases `GeoSite.dat` and `GeoIP.dat` (~27 MB, several mirrors tried in order, SHA256-verified); afterwards the cache is used. If the download fails, split routing is turned off automatically and it falls back to a global proxy — the connection still works, and **the settings page states this clearly** rather than degrading silently.

The databases are addressed by **fixed commit** (not a rolling tag like `release`), and all three mirrors return identical bytes, which is why the SHA256 check is exact. The trade-off is that the databases do not follow upstream updates automatically; to update them, a maintainer changes three places in `lib/mihomo.js`:

```js
const GEODATA_COMMIT = '3914c5cf…';   // new commit
const GEODATA_SHA256 = {
  'GeoSite.dat': '…',                 // measured SHA256 for that commit
  'GeoIP.dat': '…',
};
```

**Offline / intranet deployment**: Set `DSH_TUNNEL_GEODATA_DIR` to a directory containing `GeoSite.dat` and `GeoIP.dat`; the plugin then skips both the download and the SHA256 check and uses those files directly (you are responsible for their provenance and freshness). A missing file is reported explicitly.

```powershell
$env:DSH_TUNNEL_GEODATA_DIR = "D:\my-geodata"   # set before starting DSH
```

When `GEOSITE,cn` coverage is incomplete, add entries under **Settings → Outbound Network → Direct list**. Three forms are supported:

| Form | Example | Effect |
|---|---|---|
| Domain suffix | `example.com` | That domain and its subdomains go direct |
| IP address | `192.168.1.5`, `2001:db8::1` | That address goes direct |
| CIDR block | `10.20.30.0/24` | That block goes direct |

Changes take effect on the next connection.

Deployers can also preset a fixed direct list through plugin configuration; it is merged with the entries from the UI (configured entries come first and are not overridden by the UI):

```yaml
# cordis.patch.yml or profile config
- id: dsh-tunnel
  name: '@wanziya/dsh-tunnel'
  config:
    directHosts:
      - example.com
      - 10.20.30.0/24
```

### Pasting a config directly (no subscription URL needed)

If your current network cannot reach the subscription URL, switch to **Paste YAML**, paste a complete Clash / mihomo config, and click **Import config**. Base64-encoded or plaintext node-link lists and v2rayN single-node links (`vless://`, `vmess://`, `ss://`, `trojan://`, …) are also supported.

- Disconnect before importing; the config may be at most 6 MB.
- The config is parsed locally on the DSH server side, no request is made to the subscription URL, and nodes plus `hosts` mappings are preserved.
- After a successful import the input box and the previous subscription URL are cleared; later connections use the saved nodes. To update, re-import or enter a subscription URL.
- An imported config without a subscription URL can also be cleared with **Remove**.
- Agents can perform the same import via `tunnel_connection`'s `import` action and its `content` parameter. Do not paste configs containing passwords or tokens into a chat — prefer the settings page.

### Supported subscription formats

- Clash / Clash.Meta / mihomo YAML documents containing an inline `proxies` list.
- Base64-encoded or plaintext URI lists, supporting `ss`, `vmess`, `trojan`, `vless` (including Reality), `hysteria2`, `tuic`, `socks5` and `http` nodes.
- v2rayN single-node links (`vless://`, `vmess://`, `ss://`, `trojan://`, …), pasted into the subscription box or "Paste YAML" and parsed locally.

The plugin does not reuse proxy groups or routing rules from the subscription; it creates a fixed `select` proxy group. Domestic-direct split routing is enabled by default: traffic matching `GEOSITE,cn` and `GEOIP,CN` goes direct and only the rest uses the selected node. Local, loopback and RFC1918 private addresses always go direct. When the rule databases are missing it falls back to a global proxy.

Clash `hosts` mappings from the subscription are preserved, for compatibility with subscriptions that use a special domain as a node `server` and map it to a real CDN address via `hosts`. On connect the plugin additionally resolves every proxy server: IPv6-only nodes (IPv6 answer only) get their AAAA address pinned automatically, avoiding connection failures caused by the core's `ipv6: false`; resolution failures degrade silently and never block the connection.

## Data and security

Runtime data lives in `~/.dsh/tunnel/` under your user directory (override with the `DSH_TUNNEL_DATA_DIR` environment variable):

| Relative path | Purpose |
|---|---|
| `~/.dsh/tunnel/state.json` | Subscription URL, parsed nodes, selected node and quota info. |
| `~/.dsh/tunnel/config.yaml` | The mihomo config generated on connect. |
| `~/.dsh/tunnel/GeoSite.dat` | Domestic domain routing database. Downloaded and SHA256-verified on first connect; read from `DSH_TUNNEL_GEODATA_DIR` when set. |
| `~/.dsh/tunnel/GeoIP.dat` | IP geolocation database. Same as above. |
| `~/.dsh/tunnel/mihomo` | Fallback core downloaded when the packaged core is unavailable. |

On Linux/macOS, `state.json` and `config.yaml` are `0600` and the data directory is `0700`; Windows has no Unix permission bits, so security relies on the user-directory ACL (readable/writable by you alone by default). Removing a subscription deletes the saved subscription state.

When upgrading from 1.1.4 or earlier, the old `.data/state.json` is copied to the new directory on first start (the original is kept; you may delete it manually).

**This data can contain subscription tokens and node passwords — do not publish it or commit it to Git.** The repository excludes dependency directories and environment files via `.gitignore`. If data remains after uninstalling, delete it manually once you are sure you no longer need it; do not rely on an uninstall to preserve data.

### Security hardening

- **Subscription URL protection (SSRF)**: When importing a subscription by link, URLs pointing at loopback, private, link-local, reserved or cloud-metadata addresses are rejected, and every resolved address is checked to prevent DNS rebinding; redirects are validated hop by hop and redirecting to an internal address is forbidden.
- **Core verification**: On every platform the core binary is SHA256-verified byte by byte before launch (pinned version v1.19.33); a mismatch refuses to start. Verification is split by *file origin*: the Linux download fallback verifies the archive (`CORE_SHA256`), the extracted bare binary on disk is checked against `DOWNLOADED_CORE_SHA256`, and npm platform packages against `PACKAGED_CORE_SHA256`. On non-Linux platforms, a cached core with no `DOWNLOADED_CORE_SHA256` entry falls back to `PACKAGED_CORE_SHA256` (that binary can only be a copy of the npm package). The Linux download branch also verifies the extracted bare binary against `DOWNLOADED_CORE_SHA256` **before writing it to disk** — pinning only the archive is not enough: if the two tables ever diverge you get "download succeeds → next connect fails verification → delete and re-download → fails again".
- **Verification status is visible**: The settings page distinguishes "verified", "verification failed" and "using a custom core (unverified)" instead of showing the core as ready merely because the file exists.
- **Subscription URL masking**: State returned to the front end never exposes tokens/passwords from the subscription link (embedded credentials are replaced with `***`).
- **Certificate-check warnings**: Nodes that declare certificate verification disabled (`skip-cert-verify` / `allowInsecure`) are marked with a `!` badge in the node list, warning of a man-in-the-middle risk.
- **Insecure nodes hidden by default**: By default `skip-cert-verify` nodes are hidden (certificate verification off means MITM sniffing risk). They stay in the subscription and simply do not participate in connecting. To use them, enable "Allow insecure nodes" in the settings page; the switch is reversible and needs no re-import.

## Core and platforms

The plugin uses [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) version `1.19.33` via [`@pkgship/mihomo`](https://www.npmjs.com/package/@pkgship/mihomo). The core is distributed as per-platform npm packages, and `@pkgship/mihomo` automatically selects the matching optional dependency at install time:

| Platform | Core package |
|---|---|
| Linux x64 / arm64 | `@pkgship/mihomo-linux-amd64` / `-arm64` |
| Windows x64 / arm64 | `@pkgship/mihomo-windows-amd64` / `-arm64` |
| macOS x64 / arm64 | `@pkgship/mihomo-darwin-amd64` / `-arm64` |
| Android arm64 | `@pkgship/mihomo-android-arm64` |

None of these platforms needs a separate core download. Only when the matching platform package is unavailable does the plugin fall back to downloading a Linux core from GitHub (Linux only, SHA256-verified).

> **Upgrading from 1.1.4**: An older version may have left a core at `~/.dsh/tunnel/mihomo`. If it does not match the current pin, the first connection reports a verification failure. Delete that file as instructed in the error message and click Connect again; the plugin re-downloads a correct core.

You can also point at your own mihomo via an environment variable or plugin config (the `corePath` config wins, the environment variable is the fallback):

```bash
export DSH_TUNNEL_CORE_PATH=/absolute/path/to/mihomo
```

Set this before starting DSH. A custom core skips pin verification (you are responsible for that binary), but the path must actually exist, otherwise connecting reports a clear error. While a custom core is in use, the settings page labels it as "bytes not verified by the plugin" rather than showing it as verified.

> **Trust boundary**: The binaries for every platform come from the corresponding npm package (`@pkgship/mihomo-*`), and the plugin SHA256-verifies the binary before launch (pin values are taken from the binary extracted from the corresponding official GitHub release asset, checked byte for byte before being recorded). A failed check refuses to start and suggests falling back to a trusted core via `DSH_TUNNEL_CORE_PATH`.
>
> **Limits of pinning**: pin values live in the source, so anyone who can change both the binary and the pin can of course bypass it. This check defends against attacks that alter a single link — "npm package contents swapped", "cache file tampered with" — not against everything.
>
> If you need stronger guarantees for the core supply chain, point `DSH_TUNNEL_CORE_PATH` at a mihomo executable you verified yourself.

mihomo is licensed **GPL-3.0-or-later**, independent of this plugin's MIT source license (see the next section).

## Limitations

- Proxy scope is limited to the DSH process tree; other applications on the machine are unaffected.
- No TUN, no system-level DNS changes, no system proxy switching.
- When importing a subscription by link, the subscription URL must be reachable over the current direct network or a proxy DSH already has configured; if it is not, use **Paste YAML** to import directly.
- If the selected node cannot reach the services DSH depends on, those requests fail while connected; disconnecting restores direct access.
- Domestic-direct split routing depends on the rule databases. If they are unavailable (download failed and `DSH_TUNNEL_GEODATA_DIR` not configured), that connection automatically falls back to a global proxy, the settings page says so clearly, and domestic traffic also goes through the node.
- The databases are pinned to a fixed commit and do not follow upstream updates automatically; add missing domestic sites to the direct list.
- The management page is integrated into the existing DSH web UI via a React slot: it does not replace the app root, does not use an iframe, and does not read other plugins' DOM.

## License

This plugin's source is under the [MIT License](LICENSE).

```text
MIT License

Copyright (c) 2026 luchiwanzi
```

The npm package `@wanziya/dsh-tunnel` is the same source under the same license, and `package.json` sets `license` to `MIT`. MIT permits free use, modification, redistribution and commercial use; the only requirement is to retain the copyright and permission notice above.

> Note: MIT covers only this repository's plugin source. The [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) core it depends on at runtime is licensed **GPL-3.0-or-later**; the two are independent, and this plugin's MIT declaration does not change the core's license.

## Origin and credits

This project was cut down, refactored and rebuilt from [DimonHo/dsh-vpn](https://github.com/DimonHo/dsh-vpn), with security hardening added on top (SSRF protection, core SHA256 verification, subscription credential masking, certificate-check risk warnings, and more) plus engineering fixes. Thanks to the original author for their work.

## Development

After installing dependencies, run the full check (syntax, lint, unit tests):

```bash
pnpm install
pnpm lint     # eslint.config.js
pnpm test     # the ip / resolve / subscription suites under test/
```

Syntax check only:

```bash
node --check index.js
node --check client.js
node --check lib/subscription.js
node --check lib/mihomo.js
node --check lib/resolve.js
node --check lib/ip.js
```

CI (`.github/workflows/ci.yml`) runs exactly the above; running it locally before committing is enough.

### Publishing to npm

Package name `@wanziya/dsh-tunnel`. Publishing requires an npm account whose token has `publish` permission (with Bypass 2FA enabled):

```bash
pnpm publish --access public
```

After publishing, bump `version` in `package.json` and push it back to this repository so npm and GitHub stay in sync.

The host side uses native ESM; the client side uses a lazily executed `window.__ModuleLoader__` factory and imports `react` only from the browser module table.
