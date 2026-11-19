# DSH Tunnel · 外网连接

**为 DeepSeek Harness 提供一条可控的出站网络：让模型请求、联网工具和 MCP 走你选的代理节点，并让国内流量保持直连。**

模型请求由 **DSH 进程自己** 发出，不是由你浏览器发出。所以「页面能打开」不代表模型接口能连上，「浏览器能访问国外网站」也不代表 DSH 能访问——尤其在国内云服务器上部署时，出站受限是常态。插件把这件事放进 DSH 自己的设置页：不用改系统代理、不动路由表，也不需要给整台机器套全局代理。

桌面版和云服务器部署都适用。典型流程是 **导入订阅或粘贴 YAML → 选择节点 → 连接 → 测试出口 IP**。

## 解决什么问题？

| 常见痛点 | 本插件提供的能力 |
|---|---|
| DSH 已部署成功，但调用 OpenAI、Anthropic 等国外模型接口时连接失败或超时 | 为 DSH 模型请求配置代理出口，解决网络可达性问题。 |
| 本地电脑能访问国外服务，但服务器上的 DSH 仍然无法连接 | 代理作用于 DSH 进程本身，而不是只作用于浏览器。 |
| 不想修改整台机器的网络配置，影响其他应用 | 仅为 DSH 及其后续启动的子进程提供代理，不修改系统代理、防火墙或路由表。 |
| 连订阅地址都无法访问，无法拉取节点 | 支持直接粘贴 Clash / mihomo YAML 或节点列表，在本地解析。 |
| 模型可用，但联网搜索、网页抓取等工具仍受网络限制 | 通过 DSH 进程级代理策略覆盖 `web_search` / `web_fetch`、MCP 等支持该策略的请求。 |
| 全局代理后国内服务也绕道境外，变慢甚至失败 | 国内直连分流：国内流量不经过节点，只有其余流量走代理；覆盖不全时可用直连名单补充。 |

> **能力边界：本插件解决的是网络连接问题，不提供模型账号、API Key、订阅额度或代理节点。** 需要自行准备可用节点和相应模型凭据；实际可用性取决于节点质量、服务商支持地区、账号权限及服务条款，不能保证所有国外模型均可使用。
>
> 本插件不是系统级代理或 TUN 工具，不修改系统网络配置，也不会自动代理你本地浏览器中的登录授权页面。请遵守所在地适用法律及相关服务条款。

## 安装

### 命令行安装

在运行 DSH 的机器上执行（需要已安装 Git）：

```bash
dsh plugin --profile <profile> add 'git+https://github.com/luchiwanzi/dsh-tunnel.git'
```

`<profile>` 换成你实际使用的 profile 名：桌面版默认是 `desktop`，命令行版默认是 `web`。不确定的话看 `~/.dsh/profiles/` 下的目录名。

安装后刷新 DSH 页面，在 **设置 → 外网连接** 中使用。若未出现，重启 DSH。

### 插件管理页面安装

打开 **插件管理 → 添加插件**，输入以下 Git 地址并安装：

```text
git+https://github.com/luchiwanzi/dsh-tunnel.git
```

### 卸载

```bash
dsh plugin --profile <profile> remove dsh-tunnel
```

卸载前建议先断开连接；需要保留订阅配置时，请提前妥善备份运行数据。

## 主要功能

- **订阅导入**：支持 Clash / mihomo YAML 订阅、Base64 编码或明文节点链接列表，以及 v2rayN 的单节点链接（`vless://`、`vmess://`、`ss://`、`trojan://` 等）。
- **节点切换**：在设置页面选择节点、连接或断开代理。
- **出口测试**：检查当前公网出口 IP。
- **DSH 范围代理**：连接后应用 DSH 进程级 HTTP 代理策略，供模型请求、`web_search` / `web_fetch`、MCP 和后续启动的子进程使用。
- **本地监听**：HTTP/SOCKS 混合代理仅绑定 `127.0.0.1` 的随机端口，管理接口复用现有 DSH Web 服务。
- **纯 IPv6 节点支持**：连接前自动解析各代理服务器域名，将「仅解析出 IPv6 地址」的节点钉进 `hosts`，使只有 AAAA 记录的纯 IPv6 节点也能连接；有 IPv4 答案或解析失败的节点保持原有解析路径，不影响连接。
- **国内直连分流**：`GEOSITE,cn` 与 `GEOIP,CN` 命中的流量直连，其余流量才走所选节点。规则数据库（`GeoSite.dat` / `GeoIP.dat`，约 27 MB）在首次连接时自动下载并校验 SHA256；也可用 `DSH_TUNNEL_GEODATA_DIR` 指定本地目录离线提供。数据库不可用时回退为全局代理，并在设置页明确提示。
- **直连名单**：国内分流覆盖不全时，可在设置页手动补充需要直连的域名、IP 或网段。
- **智能体工具**：提供 `tunnel_connection`，支持查询状态、导入订阅、连接、断开、切换节点和测试出口。

## 使用方法

1. 打开侧边栏底部的 **设置 → 外网连接**。
2. 粘贴订阅地址，点击 **保存并解析**。
3. 选择一个节点，点击 **连接**。
4. 点击 **测试出口**，检查公网 IP。
5. 不再需要代理时点击 **断开**，恢复直接连接，并移除后续子进程的代理环境配置。

在其他 DSH 安装本插件后，需要重新填写订阅；仓库不包含个人订阅、节点凭据或运行配置。

### 国内直连分流与直连名单

连接后默认启用国内直连：`GEOSITE,cn` 与 `GEOIP,CN` 命中的流量不经过节点，其余流量仍走所选节点。访问国内服务不绕路、也不消耗订阅流量。

首次连接会下载规则数据库 `GeoSite.dat` 与 `GeoIP.dat`（约 27 MB，多个镜像依次尝试，SHA256 校验），之后命中缓存。下载失败时自动关闭分流、回退为全局代理，连接不受影响——**此时设置页会给出明确提示**，不会静默降级。

数据库按**固定 commit** 寻址（而非 `release` 这类滚动标签），三个镜像返回同一份字节，因此 SHA256 校验是精确的。代价是数据库不会自动跟上游更新；需要更新时由维护者同时改动 `lib/mihomo.js` 里的三处：

```js
const GEODATA_COMMIT = '3914c5cf…';   // 新的 commit
const GEODATA_SHA256 = {
  'GeoSite.dat': '…',                 // 该 commit 实测的 SHA256
  'GeoIP.dat': '…',
};
```

**离线 / 内网部署**：设置环境变量 `DSH_TUNNEL_GEODATA_DIR` 指向一个目录，并把 `GeoSite.dat`、`GeoIP.dat` 放进去，插件就不再下载、也不做 SHA256 校验，直接使用这两个文件（文件由你自行负责其来源与时效）。缺文件时会明确报告缺哪一个。

```powershell
$env:DSH_TUNNEL_GEODATA_DIR = "D:\my-geodata"   # 启动 DSH 前设置
```

`GEOSITE,cn` 覆盖不全时，可在 **设置 → 外网连接 → 直连名单** 手动补充。支持三种写法：

| 写法 | 例子 | 作用 |
|---|---|---|
| 域名后缀 | `example.com` | 该域名及其子域直连 |
| IP 地址 | `192.168.1.5`、`2001:db8::1` | 该地址直连 |
| 网段 | `10.20.30.0/24` | 该网段直连 |

改动在下次连接时生效。

部署方也可以通过插件配置预置固定的直连名单，与界面条目合并（配置在前，不会被界面覆盖）：

```yaml
# cordis.patch.yml 或 profile 配置
- id: dsh-tunnel
  name: dsh-tunnel
  config:
    directHosts:
      - example.com
      - 10.20.30.0/24
```

### 直接粘贴配置（无需访问订阅地址）

如果当前网络无法访问订阅地址，可切换到 **粘贴 YAML**，粘贴完整 Clash / mihomo 配置，然后点击 **导入配置**。也支持 Base64 编码或明文节点链接列表，以及 v2rayN 的单节点链接（`vless://`、`vmess://`、`ss://`、`trojan://` 等）。

- 导入前需先断开连接；配置内容最大为 6 MB。
- 配置在 DSH 服务端本地解析，不向订阅地址发起请求，并保留节点与 `hosts` 映射。
- 导入成功后清空输入框和原订阅地址，后续连接使用保存的节点；更新时需要重新导入或填写订阅地址。
- 没有订阅地址的已导入配置也可以通过 **删除** 清除。
- 智能体可通过 `tunnel_connection` 的 `import` 操作及 `content` 参数执行相同导入；含密码或令牌的配置不要直接粘贴到聊天中，建议使用设置页面。

### 支持的订阅格式

- 包含内联 `proxies` 列表的 Clash / Clash.Meta / mihomo YAML 文档。
- Base64 编码或明文 URI 列表，支持 `ss`、`vmess`、`trojan`、`vless`（含 Reality）、`hysteria2`、`tuic`、`socks5` 和 `http` 节点。
- v2rayN 的单节点链接（`vless://`、`vmess://`、`ss://`、`trojan://` 等），可直接粘贴到订阅框或「粘贴 YAML」中，在本地解析。

插件不沿用订阅中的代理组和分流规则，而是创建一个固定的 `select` 代理组。默认启用国内直连分流：`GEOSITE,cn` 与 `GEOIP,CN` 命中的流量直连，其余流量才走所选节点。本地、回环和 RFC1918 私有地址始终直连。规则数据库缺失时会自动回退为全局代理。

订阅中的 Clash `hosts` 映射会保留，以兼容在节点 `server` 中使用特殊域名、再通过 `hosts` 映射到真实 CDN 地址的订阅。连接时插件会额外解析每个代理服务器：对「只返回 IPv6 地址」的纯 IPv6 节点自动固定 AAAA 地址，避免因内核 `ipv6: false` 而无法连接；解析失败会静默降级，绝不阻断连接。

## 数据与安全

运行数据保存在插件目录下的 `.data/` 中：

| 相对路径 | 用途 |
|---|---|
| `.data/state.json` | 订阅地址、解析后的节点、所选节点及配额信息，权限为 `0600`。 |
| `.data/config.yaml` | 连接时生成的 mihomo 配置，权限为 `0600`。 |
| `.data/GeoSite.dat` | 国内域名路由数据库，权限为 `0600`。首次连接自动下载并校验 SHA256；设置了 `DSH_TUNNEL_GEODATA_DIR` 时改从该目录读取。 |
| `.data/GeoIP.dat` | IP 归属数据库，权限为 `0600`。同上。 |
| `.data/mihomo` | 打包内核不可用时下载的备用内核。 |

数据目录权限为 `0700`，仅允许所有者访问。移除订阅会删除保存的订阅状态。

**这些数据可能包含订阅令牌和节点密码，请勿公开或提交到 Git。** 仓库已通过 `.gitignore` 排除 `.data/`、依赖目录和环境变量文件。卸载后若仍有残留数据，可在确认不再需要后手动删除；不要依赖卸载保留数据。

### 安全加固

- **订阅地址防护（防 SSRF）**：通过链接导入订阅时，插件会拒绝指向回环、私有、链路本地、保留及云元数据地址的 URL，并在解析域名后逐条校验，防止 DNS 重绑定；重定向会逐跳校验，禁止跳转到内网地址。
- **内核校验**：从 GitHub 下载备用 mihomo 内核时，会校验压缩包的 SHA256（固定版本），不匹配即中止，防止供应链投毒。
- **订阅 URL 脱敏**：返回给前端的状态不会暴露订阅链接中的令牌/密码（内嵌凭据会以 `***` 替换）。
- **证书校验提示**：订阅中声明禁用证书校验（`skip-cert-verify` / `allowInsecure`）的节点会在节点列表中标记 `!` 徽标，提示存在中间人风险。
- **默认拒绝不安全节点**：默认情况下会过滤掉 `skip-cert-verify` 节点（关闭证书校验，存在中间人嗅探风险）。如需使用这类节点，可在设置页开启「允许不安全节点」开关，开启后需重新导入订阅才会保留这些节点。

## 内核与平台

插件通过 [`@pkgship/mihomo`](https://www.npmjs.com/package/@pkgship/mihomo) 使用版本为 `1.19.33` 的 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 内核。内核按平台分发为独立的 npm 包，安装时由 `@pkgship/mihomo` 自动选择对应的可选依赖：

| 平台 | 内核包 |
|---|---|
| Linux x64 / arm64 | `@pkgship/mihomo-linux-amd64` / `-arm64` |
| Windows x64 / arm64 | `@pkgship/mihomo-windows-amd64` / `-arm64` |
| macOS x64 / arm64 | `@pkgship/mihomo-darwin-amd64` / `-arm64` |
| Android arm64 | `@pkgship/mihomo-android-arm64` |

以上平台都不需要单独下载内核。只有当对应平台包不可用时，插件才会退回「从 GitHub 下载 Linux 内核」这条路径（仅 Linux，含 SHA256 校验）。

也可以用环境变量指定自己准备的 mihomo：

```bash
export DSH_TUNNEL_CORE_PATH=/absolute/path/to/mihomo
```

请在启动 DSH 前设置该变量。

> **信任边界说明**：各平台的二进制都由对应的 npm 包（`@pkgship/mihomo-*`）提供，其信任来自 npm registry 的发布流程。只有 Linux AMD64/ARM64 的「从 GitHub 下载回退路径」会额外做 SHA256 校验（校验值取自 GitHub release 的 digest）。
>
> 若对内核供应链有更高要求，可通过 `DSH_TUNNEL_CORE_PATH` 指定一个你自己校验过的 mihomo 可执行文件。

mihomo 使用 **GPL-3.0-or-later** 许可证，与本插件源码的 MIT 许可相互独立（详见下节）。

## 使用限制

- 代理范围仅限 DSH 进程树，不影响机器上的其他应用。
- 不提供 TUN、系统级 DNS 修改或系统代理切换。
- 通过链接导入订阅时，订阅地址必须能通过当前直连网络或 DSH 已配置的代理访问；无法访问时可改用 **粘贴 YAML** 直接导入。
- 如果所选节点无法访问 DSH 依赖的服务，连接期间对应请求会失败；断开代理可恢复直连。
- 国内直连分流依赖规则数据库。数据库不可用（下载失败且未配置 `DSH_TUNNEL_GEODATA_DIR`）时，本次连接自动回退为全局代理，设置页会明确提示，国内流量也会走节点。
- 数据库按固定 commit 打包，不会自动跟进上游更新；国内站点若有遗漏，用直连名单补充。
- 管理页面通过 React 插槽集成到现有 DSH Web 界面，不替换应用根节点、不使用 iframe，也不读取其他插件的 DOM。

## 许可证

本插件的源码采用 [MIT 许可证](LICENSE)。

```text
MIT License

Copyright (c) 2026 luchiwanzi
```

> 说明：MIT 仅适用于本仓库的插件源码。插件运行时依赖的 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 内核采用 **GPL-3.0-or-later** 许可证，二者相互独立，本插件的 MIT 声明不会改变内核的许可证。

## 来源与致谢

本项目由 [DimonHo/dsh-vpn](https://github.com/DimonHo/dsh-vpn) 删改、重构并重新编译而来，在其基础上进行了安全加固（SSRF 防护、内核 SHA256 校验、订阅凭据脱敏、证书校验风险提示等）与工程修复。特此致谢原作者的贡献。

## 开发

安装依赖后，跑完整检查（语法、lint、单元测试）：

```bash
pnpm install
pnpm lint     # eslint.config.js
pnpm test     # test/ 下的 ip / resolve / subscription 三组用例
```

只做语法检查时：

```bash
node --check index.js
node --check client.js
node --check lib/subscription.js
node --check lib/mihomo.js
node --check lib/resolve.js
node --check lib/ip.js
```

CI（`.github/workflows/ci.yml`）跑的就是上面这套；提交前本地跑一遍即可。

Host 端使用原生 ESM；Client 端采用延迟执行的 `window.__ModuleLoader__` 工厂，并仅从浏览器模块表导入 `react`。
