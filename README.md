# DSH Tunnel · 外网连接

**面向部署在国内云服务器上的 DeepSeek Harness，解决因服务器出站网络受限，导致国外大模型接口无法连接、请求超时的痛点。**

DSH 页面能打开，不代表服务器能访问模型接口；你电脑上的浏览器能访问国外服务，也不代表云服务器上的 DSH 能访问。模型请求由 **DSH 所在服务器** 发出，因此需要为服务器上的 DSH 配置可用的出站网络。

本插件将这个配置过程放进 DSH 设置页面：**导入订阅或粘贴 YAML → 选择节点 → 连接 → 测试出口 IP**，让 DSH 通过你提供的代理节点访问国外大模型服务，无需手动修改系统代理或路由表。

## 解决什么问题？

| 国内云服务器部署中的常见痛点 | 本插件提供的能力 |
|---|---|
| DSH 已部署成功，但调用 OpenAI、Anthropic 等国外模型接口时连接失败或超时 | 为 DSH 模型请求配置代理出口，解决网络可达性问题。 |
| 本地电脑能访问国外服务，但服务器上的 DSH 仍然无法连接 | 代理作用于 DSH 服务端，而不是只作用于本地浏览器。 |
| 不想修改整台服务器的网络配置，影响其他应用 | 仅为 DSH 及其后续启动的子进程提供代理，不修改系统代理、防火墙或路由表。 |
| 服务器连订阅地址都无法访问，无法拉取节点 | 支持直接粘贴 Clash / mihomo YAML 或节点列表，在服务器本地解析。 |
| 模型可用，但联网搜索、网页抓取等工具仍受网络限制 | 通过 DSH 进程级代理策略覆盖 `web_search` / `web_fetch`、MCP 等支持该策略的请求。 |

> **能力边界：本插件解决的是网络连接问题，不提供模型账号、API Key、订阅额度或代理节点。** 需要自行准备可用节点和相应模型凭据；实际可用性取决于节点质量、服务商支持地区、账号权限及服务条款，不能保证所有国外模型均可使用。
>
> 本插件不是系统级代理或 TUN 工具，不修改系统网络配置，也不会自动代理你本地浏览器中的登录授权页面。请遵守所在地适用法律及相关服务条款。

## 安装

### 命令行安装

在运行 DSH 的机器上执行（需要已安装 Git）：

```bash
dsh plugin --profile web add 'git+https://github.com/luchiwanzi/dsh-tunnel.git'
```

使用自定义 profile 时，将 `web` 替换为实际名称。

安装后刷新 DSH 页面，在 **设置 → 外网连接** 中使用。若未出现，重启 DSH。

### 插件管理页面安装

打开 **插件管理 → 添加插件**，输入以下 Git 地址并安装：

```text
git+https://github.com/luchiwanzi/dsh-tunnel.git
```

### 卸载

```bash
dsh plugin --profile web remove dsh-tunnel
```

卸载前建议先断开连接；需要保留订阅配置时，请提前妥善备份运行数据。

## 主要功能

- **订阅导入**：支持 Clash / mihomo YAML 订阅、Base64 编码或明文节点链接列表，以及 v2rayN 的单节点链接（`vless://`、`vmess://`、`ss://`、`trojan://` 等）。
- **节点切换**：在设置页面选择节点、连接或断开代理。
- **出口测试**：检查当前公网出口 IP。
- **DSH 范围代理**：连接后应用 DSH 进程级 HTTP 代理策略，供模型请求、`web_search` / `web_fetch`、MCP 和后续启动的子进程使用。
- **本地监听**：HTTP/SOCKS 混合代理仅绑定 `127.0.0.1` 的随机端口，管理接口复用现有 DSH Web 服务。
- **纯 IPv6 节点支持**：连接前自动解析各代理服务器域名，将「仅解析出 IPv6 地址」的节点钉进 `hosts`，使只有 AAAA 记录的纯 IPv6 节点也能连接；有 IPv4 答案或解析失败的节点保持原有解析路径，不影响连接。
- **智能体工具**：提供 `tunnel_connection`，支持查询状态、导入订阅、连接、断开、切换节点和测试出口。

## 使用方法

1. 打开侧边栏底部的 **设置 → 外网连接**。
2. 粘贴订阅地址，点击 **保存并解析**。
3. 选择一个节点，点击 **连接**。
4. 点击 **测试出口**，检查公网 IP。
5. 不再需要代理时点击 **断开**，恢复直接连接，并移除后续子进程的代理环境配置。

在其他 DSH 安装本插件后，需要重新填写订阅；仓库不包含个人订阅、节点凭据或运行配置。

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

插件不沿用订阅中的代理组和分流规则，而是创建一个固定的 `select` 代理组，通过 `MATCH` 规则代理非本地流量。本地、回环和 RFC1918 私有地址保持直连。

订阅中的 Clash `hosts` 映射会保留，以兼容在节点 `server` 中使用特殊域名、再通过 `hosts` 映射到真实 CDN 地址的订阅。连接时插件会额外解析每个代理服务器：对「只返回 IPv6 地址」的纯 IPv6 节点自动固定 AAAA 地址，避免因内核 `ipv6: false` 而无法连接；解析失败会静默降级，绝不阻断连接。

## 数据与安全

运行数据保存在插件目录下的 `.data/` 中：

| 相对路径 | 用途 |
|---|---|
| `.data/state.json` | 订阅地址、解析后的节点、所选节点及配额信息，权限为 `0600`。 |
| `.data/config.yaml` | 连接时生成的 mihomo 配置，权限为 `0600`。 |
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

插件通过 [`@pkgship/mihomo`](https://www.npmjs.com/package/@pkgship/mihomo) 使用版本为 `1.19.33` 的 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 内核，Linux AMD64 二进制由 [`@pkgship/mihomo-linux-amd64`](https://www.npmjs.com/package/@pkgship/mihomo-linux-amd64) 提供。

若对应平台包不可用，插件会尝试从 GitHub 下载固定版本的 Linux 内核，并校验其 SHA256 校验和后再执行。也可通过环境变量指定已安装的 mihomo：

```bash
export DSH_TUNNEL_CORE_PATH=/absolute/path/to/mihomo
```

请在启动 DSH 前设置该变量。默认内核方案面向 Linux；其他系统可能需要自行提供适配平台的 mihomo，兼容性需另行验证。

> **信任边界说明**：只有 Linux AMD64/ARM64 的「从 GitHub 下载回退路径」会对二进制做 SHA256 校验（校验值取自 GitHub release 的 digest）。其他平台（Windows / macOS / Android）的二进制由对应的 npm 包（`@pkgship/mihomo-*`）提供，其信任来自 npm registry 的发布流程，而非 GitHub release 摘要。若对非 Linux 平台的内核供应链有更高要求，建议通过 `DSH_TUNNEL_CORE_PATH` 自行指定经过校验的 mihomo 可执行文件。

mihomo 使用 **GPL-3.0-or-later** 许可证；插件源码与内核分开，插件的许可证声明不会改变内核的许可证。

## 使用限制

- 代理范围仅限 DSH 进程树，不影响机器上的其他应用。
- 不提供 TUN、系统级 DNS 修改或系统代理切换。
- 通过链接导入订阅时，订阅地址必须能通过当前直连网络或 DSH 已配置的代理访问；无法访问时可改用 **粘贴 YAML** 直接导入。
- 如果所选节点无法访问 DSH 依赖的服务，连接期间对应请求会失败；断开代理可恢复直连。
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

安装依赖并检查 JavaScript 语法：

```bash
pnpm install
node --check index.js
node --check client.js
node --check lib/subscription.js
node --check lib/mihomo.js
```

Host 端使用原生 ESM；Client 端采用延迟执行的 `window.__ModuleLoader__` 工厂，并仅从浏览器模块表导入 `react`。
