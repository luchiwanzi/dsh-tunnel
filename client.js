window.__ModuleLoader__.load({
  id: 'dsh-tunnel',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useEffect, useMemo, useState } = React;

    const NS = 'dsh-tunnel';
    const API = '/dsh-tunnel/api';

    const en = {
      nav: 'External Network',
      title: 'External Network',
      subtitle: 'Route Harness traffic through a subscription node. The system proxy and OS routing table are never changed.',
      statusIdle: 'Not connected',
      statusDownloading: 'Preparing core…',
      statusPreparing: 'Preparing…',
      statusPreparingFirst: 'Preparing… the first connection downloads the routing database, about 30–60s.',
      statusStartingFirst: 'Starting core… the first connection takes about 30–60s.',
      statusStarting: 'Starting core…',
      statusConnected: 'Connected',
      statusStopping: 'Disconnecting…',
      statusError: 'Needs attention',
      badgeOn: 'On',
      badgeOff: 'Off',
      badgeBusy: 'Working',
      badgeError: 'Error',
      connection: 'Connection',
      connect: 'Connect',
      disconnect: 'Disconnect',
      connecting: 'Connecting…',
      stopping: 'Stopping…',
      subscriptionTitle: 'Subscription',
      subscriptionHint: 'Paste a Clash / mihomo subscription URL, or a base64 node list. Nodes are parsed locally.',
      subscriptionPlaceholder: 'https://example.com/api/v1/client/subscribe?token=…',
      urlMode: 'Subscription URL',
      yamlMode: 'Paste YAML',
      yamlHint: 'Paste a Clash / mihomo YAML, or a single v2rayN node link (vless://, vmess://, ss://, trojan://, …). It is parsed locally.',
      yamlPlaceholder: 'hosts:\n  "fake.example": "real.example"\nproxies:\n  - name: Example\n    type: ss\n    server: fake.example\n    port: 443\n    cipher: aes-128-gcm\n    password: …',
      importYaml: 'Import config',
      importing: 'Importing…',
      yamlRequired: 'Paste a YAML config first.',
      configImported: 'Config imported.',
      yamlPrivacy: 'The raw text is cleared after import; only parsed nodes and hosts are saved.',
      saveSubscription: 'Save & parse',
      updating: 'Parsing…',
      clearSubscription: 'Remove',
      clearConfirm: 'Remove the saved subscription and all nodes?',
      urlRequired: 'Enter a subscription URL first.',
      subscriptionSaved: 'Subscription parsed.',
      subscriptionCleared: 'Subscription removed.',
      nodeSelected: 'Node selected:',
      nodes: 'nodes',
      updatedAt: 'Updated',
      expiresAt: 'Expires',
      traffic: 'Traffic',
      unlimited: 'Unlimited',
      unknown: 'Unknown',
      nodeTitle: 'Nodes',
      nodeHint: 'Pick the egress node. “Test all” measures the local core’s TCP handshake to the node.',
      searchPlaceholder: 'Filter nodes…',
      testAll: 'Test all',
      testing: 'Testing…',
      noNodes: 'No nodes yet',
      noNodesHint: 'Add a subscription above. The first connection downloads the mihomo core (about 22 MB).',
      selectedNode: 'Selected',
      selectNode: 'Select',
      exitTitle: 'Egress check',
      exitHint: 'Fetches a public IP echo through the selected node.',
      testExit: 'Test exit',
      testingExit: 'Testing…',
      exitIp: 'Exit IP',
      endpoint: 'Local endpoint',
      coreVersion: 'Core',
      connectedNotice: 'Connected. Harness traffic now uses the selected node.',
      disconnectedNotice: 'Disconnected. Direct access restored.',
      exitResult: 'Exit IP:',
      latencyDone: 'Latency test finished.',
      scopeTitle: 'Scope',
      scopeBody: 'Only the current Harness process: model requests, web_search / web_fetch, MCP, and subprocesses started afterwards. No system proxy, no TUN, no OS network changes.',
      securityNote: 'Subscription and node credentials are stored in this plugin’s local data directory with owner-only permissions.',
      firstRunNote: 'First connection downloads a pinned mihomo core (about 22 MB) from GitHub. Later connections reuse it.',
      noCore: 'Core not downloaded yet.',
      errorTitle: 'Operation failed',
      noticeTitle: 'Done',
      dismiss: 'Dismiss',
      loading: 'Reading tunnel state…',
      clearNeedsDisconnect: 'Disconnect before removing the subscription.',
      updateNeedsDisconnect: 'Disconnect before updating the subscription.',
      startHint: 'Add a subscription, then connect.',
      directHint: 'Traffic currently goes direct.',
      proxyHint: 'Local mixed proxy is active.',
      group: 'Group',
      firstStep: 'Paste a subscription',
      secondStep: 'Choose a node',
      thirdStep: 'Connect and test the exit IP',
      insecureNode: 'Certificate verification disabled',
      allowInsecure: 'Allow insecure nodes',
      allowInsecureHint: 'Reject nodes with skip-cert-verify by default (recommended). Enable only if you trust the subscription and accept the man-in-the-middle risk.',
      allowInsecureOn: 'Insecure nodes are now allowed.',
      allowInsecureOff: 'Insecure nodes are now rejected.',
      directListTitle: 'Direct domains',
      directListHint: 'Domestic traffic already goes direct. Add sites that should too — a hostname, a domain suffix, an IP, or a CIDR block.',
      directPlaceholder: 'example.com, corp.internal, 10.20.30.0/24',
      directAdd: 'Add',
      directEmpty: 'No extra direct sites. Domestic traffic goes direct automatically.',
      directRemove: 'Remove',
      directInvalid: 'That is neither a hostname nor an IP address.',
      directDuplicate: 'Already in the list.',
      directSaved: 'Direct list updated.',
      directNeedsDisconnect: 'Disconnect before changing the direct list.',
      directNote: 'Changes apply on the next connection.',
    };

    const zh = {
      nav: '外网连接',
      title: '外网连接',
      subtitle: '通过订阅节点转发 Harness 的网络流量。不会修改系统代理或操作系统路由表。',
      statusIdle: '未连接',
      statusDownloading: '正在准备内核…',
      statusPreparing: '正在准备…',
      statusPreparingFirst: '正在准备…首次连接需下载分流数据库，约 30～60 秒。',
      statusStartingFirst: '正在启动内核…首次连接约需 30～60 秒。',
      statusStarting: '正在启动内核…',
      statusConnected: '已连接',
      statusStopping: '正在断开…',
      statusError: '需要处理',
      badgeOn: '已开启',
      badgeOff: '未开启',
      badgeBusy: '处理中',
      badgeError: '异常',
      connection: '连接状态',
      connect: '连接',
      disconnect: '断开',
      connecting: '正在连接…',
      stopping: '正在断开…',
      subscriptionTitle: '订阅',
      subscriptionHint: '粘贴 Clash / mihomo 订阅链接，或 Base64 节点列表。节点在本地解析。',
      subscriptionPlaceholder: 'https://example.com/api/v1/client/subscribe?token=…',
      urlMode: '订阅链接',
      yamlMode: '粘贴 YAML',
      yamlHint: '粘贴 Clash / mihomo YAML 配置，或 v2rayN 的单节点链接（vless://、vmess://、ss://、trojan:// 等），节点在本地解析。',
      yamlPlaceholder: 'hosts:\n  "fake.example": "real.example"\nproxies:\n  - name: 示例节点\n    type: ss\n    server: fake.example\n    port: 443\n    cipher: aes-128-gcm\n    password: …',
      importYaml: '导入配置',
      importing: '导入中…',
      yamlRequired: '请先粘贴 YAML 配置。',
      configImported: '配置已导入。',
      yamlPrivacy: '导入成功后原始文本会清空，只保存解析后的节点和 hosts 映射。',
      saveSubscription: '保存并解析',
      updating: '解析中…',
      clearSubscription: '删除',
      clearConfirm: '删除已保存的订阅和全部节点？',
      urlRequired: '请先填写订阅链接。',
      subscriptionSaved: '订阅解析完成。',
      subscriptionCleared: '订阅已删除。',
      nodeSelected: '已选择节点：',
      nodes: '个节点',
      updatedAt: '更新于',
      expiresAt: '到期',
      traffic: '流量',
      unlimited: '不限量',
      unknown: '未知',
      nodeTitle: '节点',
      nodeHint: '选择出口节点。“测速全部”通过本地内核测量到节点的握手延迟。',
      searchPlaceholder: '筛选节点…',
      testAll: '测速全部',
      testing: '测速中…',
      noNodes: '还没有节点',
      noNodesHint: '先在上方添加订阅。首次连接会下载约 22 MB 的 mihomo 内核。',
      selectedNode: '已选择',
      selectNode: '选择',
      exitTitle: '出口检测',
      exitHint: '通过当前节点请求公网 IP 回显服务。',
      testExit: '测试出口',
      testingExit: '测试中…',
      exitIp: '出口 IP',
      endpoint: '本地端口',
      coreVersion: '内核',
      connectedNotice: '已连接。Harness 流量现在走选中的节点。',
      disconnectedNotice: '已断开，已恢复直连。',
      exitResult: '出口 IP：',
      latencyDone: '测速完成。',
      scopeTitle: '作用范围',
      scopeBody: '仅影响当前 Harness 进程：模型请求、web_search / web_fetch、MCP，以及之后启动的子进程。不设置系统代理，不创建 TUN，不修改操作系统网络。',
      securityNote: '订阅和节点凭据保存在本插件的数据目录，仅当前用户可读写。',
      firstRunNote: '首次连接会从 GitHub 下载固定版本的 mihomo 内核（约 22 MB），后续连接直接复用。',
      noCore: '尚未下载内核。',
      errorTitle: '操作失败',
      noticeTitle: '完成',
      dismiss: '关闭',
      loading: '正在读取隧道状态…',
      clearNeedsDisconnect: '请先断开连接，再删除订阅。',
      updateNeedsDisconnect: '请先断开连接，再更新订阅。',
      startHint: '添加订阅后即可连接。',
      directHint: '当前为直连。',
      proxyHint: '本地混合代理已生效。',
      group: '代理组',
      firstStep: '粘贴订阅',
      secondStep: '选择节点',
      thirdStep: '连接并测试出口 IP',
      insecureNode: '未校验证书',
      allowInsecure: '允许不安全节点',
      allowInsecureHint: '默认拒绝 skip-cert-verify（关闭证书校验）节点，存在中间人风险。仅在信任该订阅并接受风险时开启。',
      allowInsecureOn: '已允许不安全节点。',
      allowInsecureOff: '已拒绝不安全节点。',
      directListTitle: '直连名单',
      directListHint: '国内流量已默认直连。这里补充需要直连的站点：可填域名、域名后缀、IP 或网段。',
      directPlaceholder: 'example.com、corp.internal、10.20.30.0/24',
      directAdd: '添加',
      directEmpty: '暂无额外直连站点。国内流量已自动直连。',
      directRemove: '删除',
      directInvalid: '既不是域名也不是 IP 地址。',
      directDuplicate: '已在列表中。',
      directSaved: '直连名单已更新。',
      directNeedsDisconnect: '请先断开连接，再修改直连名单。',
      directNote: '下次连接时生效。',
    };

    const CSS = `
.dshtunnel-root{max-width:820px;margin:0 auto;padding:18px 2px 48px;color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.5}
.dshtunnel-root *{box-sizing:border-box}
.dshtunnel-head{display:flex;align-items:flex-start;gap:14px;margin:0 0 18px}
.dshtunnel-mark{width:46px;height:46px;flex:none;display:grid;place-items:center;border-radius:14px;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l1)}
.dshtunnel-head-copy{min-width:0;flex:1}
.dshtunnel-title{margin:0;font-size:20px;line-height:1.25;font-weight:650;letter-spacing:-.01em}
.dshtunnel-subtitle{margin:5px 0 0;color:var(--dsw-alias-label-secondary);max-width:620px}
.dshtunnel-badge{flex:none;display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 10px;border-radius:999px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);font-size:12px;font-weight:600;white-space:nowrap}
.dshtunnel-dot{width:7px;height:7px;border-radius:50%;background:var(--dsw-alias-state-idle-primary)}
.dshtunnel-badge.on{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
.dshtunnel-badge.on .dshtunnel-dot{background:var(--dsw-alias-state-success-primary)}
.dshtunnel-badge.busy{color:var(--dsw-alias-state-warn-primary);border-color:var(--dsw-alias-state-warn-primary)}
.dshtunnel-badge.busy .dshtunnel-dot{background:var(--dsw-alias-state-warn-primary);animation:dshtunnel-pulse 1.2s ease-in-out infinite}
.dshtunnel-badge.error{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
.dshtunnel-badge.error .dshtunnel-dot{background:var(--dsw-alias-state-error-primary)}
@keyframes dshtunnel-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.82)}}
.dshtunnel-card{background:var(--dsw-alias-bg-layer-1);border:1px solid var(--dsw-alias-border-l1);border-radius:14px;padding:18px;margin-top:14px}
.dshtunnel-hero{display:flex;gap:18px;align-items:stretch;justify-content:space-between;background:var(--dsw-alias-bg-layer-1)}
.dshtunnel-hero-copy{min-width:0;flex:1}
.dshtunnel-eyebrow{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--dsw-alias-label-secondary)}
.dshtunnel-hero-line{display:flex;align-items:center;gap:9px;margin-top:7px;font-size:18px;font-weight:650;letter-spacing:-.01em}
.dshtunnel-orb{width:10px;height:10px;border-radius:50%;background:var(--dsw-alias-state-idle-primary);flex:none}
.dshtunnel-orb.on{background:var(--dsw-alias-state-success-primary)}
.dshtunnel-orb.busy{background:var(--dsw-alias-state-warn-primary);animation:dshtunnel-pulse 1.2s ease-in-out infinite}
.dshtunnel-orb.error{background:var(--dsw-alias-state-error-primary)}
.dshtunnel-muted{margin:6px 0 0;color:var(--dsw-alias-label-secondary)}
.dshtunnel-facts{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:16px}
.dshtunnel-fact{min-width:110px}
.dshtunnel-fact-label{font-size:11px;color:var(--dsw-alias-label-secondary);margin-bottom:2px}
.dshtunnel-fact-value{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px}
.dshtunnel-hero-actions{display:flex;flex-direction:column;justify-content:center;gap:8px;min-width:132px}
.dshtunnel-btn{appearance:none;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);height:36px;padding:0 14px;border-radius:10px;font:inherit;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:7px;cursor:pointer;transition:background .15s ease,border-color .15s ease,opacity .15s ease}
.dshtunnel-btn:hover:not(:disabled){background:var(--dsw-alias-bg-overlay)}
.dshtunnel-btn:disabled{opacity:1;cursor:not-allowed;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2)}
.dshtunnel-root .dshtunnel-btn.primary{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary)}
.dshtunnel-root .dshtunnel-btn.primary:hover:not(:disabled){background:var(--dsw-alias-bg-overlay)}
.dshtunnel-root .dshtunnel-btn.primary:disabled{color:var(--dsw-alias-label-secondary);border-color:var(--dsw-alias-border-l2)}
.dshtunnel-root .dshtunnel-btn:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}
.dshtunnel-btn.danger{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary);background:transparent}
.dshtunnel-btn.danger:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
.dshtunnel-btn.link{height:auto;padding:0;border:0;background:transparent;color:var(--dsw-alias-label-secondary);font-weight:500}
.dshtunnel-btn.link:hover:not(:disabled){color:var(--dsw-alias-label-primary);background:transparent}
.dshtunnel-card-head{display:flex;align-items:flex-start;gap:14px;justify-content:space-between;margin-bottom:12px}
.dshtunnel-card-head h2{margin:0;font-size:14px;font-weight:650}
.dshtunnel-card-head p{margin:3px 0 0;color:var(--dsw-alias-label-secondary);font-size:12px}
.dshtunnel-inputrow{display:flex;gap:8px;align-items:center}
.dshtunnel-input{flex:1;min-width:0;height:38px;border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);padding:0 12px;font:inherit;outline:none}
.dshtunnel-input::placeholder{color:var(--dsw-alias-label-secondary)}
.dshtunnel-input:focus{border-color:var(--dsw-alias-brand-primary);box-shadow:0 0 0 1px var(--dsw-alias-brand-primary)}
.dshtunnel-input:disabled{opacity:.6}
.dshtunnel-directlist{flex-wrap:wrap;gap:8px}
.dshtunnel-directlist .dshtunnel-step{gap:6px}
.dshtunnel-directlist code{font-size:12px}
.dshtunnel-meta{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;margin-top:10px;color:var(--dsw-alias-label-secondary);font-size:12px}
.dshtunnel-meta b{color:var(--dsw-alias-label-primary);font-weight:600}
.dshtunnel-warn{margin:10px 0 0;padding:8px 10px;border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-state-warn-primary);font-size:12px}
.dshtunnel-list{margin-top:10px;max-height:310px;overflow:auto;border-top:1px solid var(--dsw-alias-border-l1);padding-top:6px}
.dshtunnel-node{width:100%;display:flex;align-items:center;gap:10px;padding:9px 10px;border:1px solid transparent;border-radius:10px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;text-align:left;cursor:pointer}
.dshtunnel-node:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
.dshtunnel-node:disabled{opacity:.6;cursor:not-allowed}
.dshtunnel-node.selected{border-color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-bg-layer-2)}
.dshtunnel-radio{width:14px;height:14px;flex:none;border-radius:50%;border:1.5px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base)}
.dshtunnel-node.selected .dshtunnel-radio{border-color:var(--dsw-alias-brand-primary);box-shadow:inset 0 0 0 3px var(--dsw-alias-brand-primary)}
.dshtunnel-node-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12.5px}
.dshtunnel-type{flex:none;font-size:10px;line-height:1;padding:4px 6px;border-radius:6px;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-secondary);text-transform:uppercase;letter-spacing:.03em}
.dshtunnel-insecure{flex:none;width:16px;height:16px;line-height:16px;text-align:center;font-size:11px;font-weight:700;border-radius:50%;color:#fff;background:var(--dsw-alias-state-warning-primary,#d97706);cursor:help}
.dshtunnel-delay{flex:none;width:56px;text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;color:var(--dsw-alias-label-secondary)}
.dshtunnel-delay.good{color:var(--dsw-alias-state-success-primary)}
.dshtunnel-delay.warn{color:var(--dsw-alias-state-warn-primary)}
.dshtunnel-delay.bad{color:var(--dsw-alias-state-error-primary)}
.dshtunnel-empty{border:1px dashed var(--dsw-alias-border-l2);border-radius:12px;padding:20px;text-align:center;margin-top:8px}
.dshtunnel-empty strong{display:block;font-size:13px;margin-bottom:4px}
.dshtunnel-empty p{margin:0;color:var(--dsw-alias-label-secondary);font-size:12px}
.dshtunnel-steps{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:12px;color:var(--dsw-alias-label-secondary);font-size:12px}
.dshtunnel-step{display:inline-flex;align-items:center;gap:6px}
.dshtunnel-step i{display:grid;place-items:center;width:17px;height:17px;border-radius:50%;border:1px solid var(--dsw-alias-border-l2);font-style:normal;font-size:10px;color:var(--dsw-alias-label-secondary)}
.dshtunnel-alert{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-radius:10px;margin-top:12px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);font-size:12px}
.dshtunnel-alert.error{border-color:var(--dsw-alias-state-error-primary);color:var(--dsw-alias-state-error-primary)}
.dshtunnel-alert.notice{border-color:var(--dsw-alias-border-l2);color:var(--dsw-alias-label-primary)}
.dshtunnel-alert span{flex:1;min-width:0;overflow-wrap:anywhere}
.dshtunnel-alert button{appearance:none;border:0;background:transparent;color:inherit;font:inherit;cursor:pointer;opacity:.7;padding:0}
.dshtunnel-scope{display:flex;gap:12px;margin-top:18px;padding:14px 4px 0;border-top:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-secondary);font-size:12px}
.dshtunnel-scope svg{flex:none;margin-top:1px}
.dshtunnel-scope strong{display:block;color:var(--dsw-alias-label-primary);margin-bottom:3px;font-size:12px}
.dshtunnel-scope p{margin:0 0 4px}
.dshtunnel-loading{display:flex;align-items:center;justify-content:center;min-height:220px;color:var(--dsw-alias-label-secondary)}
.dshtunnel-sep{height:1px;background:var(--dsw-alias-border-l1);margin:12px 0}
.dshtunnel-allowinsecure{flex-direction:column;align-items:stretch;gap:6px}
.dshtunnel-switch{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:12px;color:var(--dsw-alias-label-primary)}
.dshtunnel-switch input{width:15px;height:15px;accent-color:var(--dsw-alias-brand-primary);cursor:pointer}
.dshtunnel-switch-label{font-weight:600}
@media (max-width:640px){
  .dshtunnel-hero{flex-direction:column}
  .dshtunnel-hero-actions{flex-direction:row;min-width:0}
  .dshtunnel-hero-actions .dshtunnel-btn{flex:1}
  .dshtunnel-inputrow{flex-direction:column;align-items:stretch}
  .dshtunnel-inputrow .dshtunnel-btn{width:100%}
  .dshtunnel-facts{gap:10px 16px}
}
`;

    function request(action, payload = {}) {
      return fetch(API, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action, ...payload }),
      }).then(async (response) => {
        const data = await response.json().catch(() => null);
        if (!response.ok) throw new Error(data?.error?.message || `HTTP ${response.status}`);
        if (data === null || data.ok !== true) throw new Error(data?.error?.message || '请求失败');
        return data;
      });
    }

    function formatBytes(value) {
      if (!Number.isFinite(value) || value <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let size = value;
      let unit = 0;
      while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
      }
      return `${size >= 100 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
    }

    function formatDate(value) {
      if (!value) return '—';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return '—';
      return date.toLocaleString();
    }

    function formatExpiry(value) {
      if (!Number.isFinite(value) || value <= 0) return '—';
      return new Date(value * 1000).toLocaleDateString();
    }

    function ToneIcon() {
      return h(
        'svg',
        { width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true },
        h('circle', { cx: 12, cy: 12, r: 8.3, stroke: 'var(--dsw-alias-brand-primary)', strokeWidth: 1.7 }),
        h('path', { d: 'M3.7 12h16.6M12 3.7c2.3 2.4 3.5 5.2 3.5 8.3s-1.2 5.9-3.5 8.3c-2.3-2.4-3.5-5.2-3.5-8.3S9.7 6.1 12 3.7Z', stroke: 'var(--dsw-alias-brand-primary)', strokeWidth: 1.5, strokeLinecap: 'round' }),
      );
    }

    function Fact({ label, value }) {
      return h(
        'div',
        { className: 'dshtunnel-fact' },
        h('div', { className: 'dshtunnel-fact-label' }, label),
        h('div', { className: 'dshtunnel-fact-value', title: value }, value),
      );
    }

    function Section(props) {
      const [snapshot, setSnapshot] = useState(null);
      const [urlDraft, setUrlDraft] = useState('');
      const [inputMode, setInputMode] = useState('url');
      const [yamlDraft, setYamlDraft] = useState('');
      const [busy, setBusy] = useState('');
      const [error, setError] = useState('');
      const [notice, setNotice] = useState('');
      const [filter, setFilter] = useState('');
      const [delays, setDelays] = useState({});
      const [directDraft, setDirectDraft] = useState('');
      const getLocale = props.locale?.get;
      const subscribeLocale = props.locale?.subscribe;
      const [activeLocale, setActiveLocale] = useState(() => getLocale?.().active ?? 'zh');

      useEffect(() => {
        if (typeof subscribeLocale !== 'function' || typeof getLocale !== 'function') return undefined;
        return subscribeLocale(() => setActiveLocale(getLocale().active));
      }, [getLocale, subscribeLocale]);

      const t = (key) => {
        const table = activeLocale === 'en' ? en : zh;
        return table[key] ?? en[key] ?? key;
      };

      useEffect(() => {
        let alive = true;
        request('state')
          .then((data) => {
            if (!alive) return;
            setSnapshot(data.state);
            setUrlDraft(data.state.subscription.url || '');
          })
          .catch((reason) => {
            if (alive) setError(reason.message);
          });
        return () => {
          alive = false;
        };
      }, []);

      useEffect(() => {
        if (busy !== 'connect' && busy !== 'disconnect') return;
        const timer = setInterval(() => {
          request('state')
            .then((data) => setSnapshot(data.state))
            .catch(() => {});
        }, 700);
        return () => clearInterval(timer);
      }, [busy]);

      const phase = snapshot?.phase || 'idle';
      const connected = snapshot?.connected === true;
      const working = busy !== '';
      // The first connect provisions the routing databases (tens of megabytes)
      // before the core can start, so it legitimately sits in `preparing` for a
      // while. Saying so up front is the difference between "it is working" and
      // "it is stuck" for someone watching a spinner.
      const firstRun = snapshot?.geodataReady === false;
      const status =
        connected
          ? t('statusConnected')
          : phase === 'error'
            ? t('statusError')
            : phase === 'downloading'
              ? t('statusDownloading')
              : phase === 'preparing'
                ? firstRun
                  ? t('statusPreparingFirst')
                  : t('statusPreparing')
                : phase === 'starting'
                  ? firstRun
                    ? t('statusStartingFirst')
                    : t('statusStarting')
                  : phase === 'stopping'
                    ? t('statusStopping')
                    : t('statusIdle');
      const tone = connected
        ? 'on'
        : phase === 'error'
          ? 'error'
          : ['downloading', 'preparing', 'starting', 'stopping'].includes(phase)
            ? 'busy'
            : 'off';
      const badge =
        connected ? t('badgeOn') : phase === 'error' ? t('badgeError') : tone === 'busy' ? t('badgeBusy') : t('badgeOff');

      const nodes = snapshot?.nodes || [];
      const visibleNodes = useMemo(() => {
        const query = filter.trim().toLowerCase();
        if (query === '') return nodes;
        return nodes.filter((node) => node.name.toLowerCase().includes(query) || node.type.toLowerCase().includes(query));
      }, [nodes, filter]);

      async function perform(label, operation) {
        setBusy(label);
        setError('');
        setNotice('');
        try {
          const data = await operation();
          if (data?.state) setSnapshot(data.state);
          return data;
        } catch (reason) {
          setError(reason instanceof Error ? reason.message : String(reason));
          return null;
        } finally {
          setBusy('');
        }
      }

      async function saveSubscription() {
        if (urlDraft.trim() === '') {
          setError(t('urlRequired'));
          return;
        }
        if (connected) {
          setError(t('updateNeedsDisconnect'));
          return;
        }
        const data = await perform('subscribe', () => request('subscribe', { url: urlDraft.trim() }));
        if (data) {
          setUrlDraft(data.state.subscription.url || '');
          setNotice(`${t('subscriptionSaved')} ${data.state.subscription.nodeCount} ${t('nodes')}`);
        }
      }

      async function importYaml() {
        if (!yamlDraft.trim()) { setError(t('yamlRequired')); return; }
        if (connected || working) return;
        const data = await perform('import', () => request('import', { content: yamlDraft }));
        if (data) {
          setYamlDraft('');
          setUrlDraft('');
          setDelays({});
          setNotice(`${t('configImported')} ${data.state.subscription.nodeCount} ${t('nodes')}`);
        }
      }

      async function connect() {
        const data = await perform('connect', () => request('connect'));
        if (!data) return;
        setNotice(t('connectedNotice'));
        setBusy('test');
        try {
          const result = await request('test');
          setSnapshot(result.state);
          setNotice(`${t('exitResult')} ${result.ip}`);
        } catch (reason) {
          setError(reason instanceof Error ? reason.message : String(reason));
        } finally {
          setBusy('');
        }
      }

      async function disconnect() {
        const data = await perform('disconnect', () => request('disconnect'));
        if (data) setNotice(t('disconnectedNotice'));
      }

      async function selectNode(node) {
        const data = await perform(`select:${node.name}`, () => request('select', { name: node.name }));
        if (data) setNotice(`${t('nodeSelected')} ${node.name}`);
      }

      async function testExit() {
        const data = await perform('test', () => request('test'));
        if (data) setNotice(`${t('exitResult')} ${data.ip}`);
      }

      async function latencyAll() {
        const data = await perform('latency:all', () => request('latency'));
        if (data) {
          setDelays((current) => ({ ...current, ...data.results }));
          setNotice(t('latencyDone'));
        }
      }

      async function latencyOne(node) {
        const data = await perform(`latency:${node.name}`, () => request('latency', { name: node.name }));
        if (data) setDelays((current) => ({ ...current, ...data.results }));
      }

      async function clearSubscription() {
        if (connected) {
          setError(t('clearNeedsDisconnect'));
          return;
        }
        if (!window.confirm(t('clearConfirm'))) return;
        const data = await perform('clear', () => request('clear'));
        if (data) {
          setUrlDraft('');
          setYamlDraft('');
          setDelays({});
          setNotice(t('subscriptionCleared'));
        }
      }

      async function addDirectHost() {
        const raw = directDraft.trim();
        if (raw === '') return;
        if (connected) {
          setError(t('directNeedsDisconnect'));
          return;
        }
        // Validate here as well as on the host: the host drops what it cannot
        // turn into a rule, so without this a typo would report success and
        // then quietly not appear.
        // Same test the host applies. Kept deliberately strict about the shape
        // of an address: a looser one lets "abc123" through to the host, which
        // drops it, and the user sees "added" then nothing.
        const isAddress =
          /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(raw) || /^[0-9a-fA-F:]+\/\d{1,3}$/.test(raw);
        const isHost = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(raw);
        if (!isAddress && !isHost) {
          setError(t('directInvalid'));
          return;
        }
        const current = snapshot?.directHosts ?? [];
        if (current.includes(raw)) {
          setError(t('directDuplicate'));
          return;
        }
        const data = await perform('direct', () =>
          request('setDirectHosts', { directHosts: [...current, raw] }),
        );
        if (data) {
          setDirectDraft('');
          setNotice(t('directSaved'));
        }
      }

      async function removeDirectHost(entry) {
        if (connected) {
          setError(t('directNeedsDisconnect'));
          return;
        }
        const current = snapshot?.directHosts ?? [];
        const data = await perform('direct', () =>
          request('setDirectHosts', { directHosts: current.filter((item) => item !== entry) }),
        );
        if (data) setNotice(t('directSaved'));
      }

      async function toggleAllowInsecure(next) {
        if (connected) {
          setError(t('updateNeedsDisconnect'));
          return;
        }
        const data = await perform('setAllowInsecure', () => request('setAllowInsecure', { allowInsecure: next }));
        if (data) setNotice(next ? t('allowInsecureOn') : t('allowInsecureOff'));
      }

      function delayClass(value) {
        if (!Number.isFinite(value)) return '';
        if (value < 350) return 'good';
        if (value < 900) return 'warn';
        return 'bad';
      }

      function renderDelay(name) {
        const value = delays[name];
        if (!Number.isFinite(value)) return '—';
        return `${value} ms`;
      }

      const shell = (children) => h('div', { className: 'dshtunnel-root' }, h('style', { key: 'style' }, CSS), children);

      if (snapshot === null) {
        return shell(h('div', { className: 'dshtunnel-loading' }, error || t('loading')));
      }

      const userinfo = snapshot.subscription.userinfo;
      const traffic =
        userinfo && Number.isFinite(userinfo.total) && userinfo.total > 0
          ? `${formatBytes((userinfo.upload || 0) + (userinfo.download || 0))} / ${formatBytes(userinfo.total)}`
          : userinfo
            ? `${formatBytes((userinfo.upload || 0) + (userinfo.download || 0))} / ${t('unlimited')}`
            : t('unknown');

      return shell([
        h(
          'div',
          { className: 'dshtunnel-head', key: 'head' },
          h('div', { className: 'dshtunnel-mark' }, h(ToneIcon)),
          h(
            'div',
            { className: 'dshtunnel-head-copy' },
            h('h1', { className: 'dshtunnel-title' }, t('title')),
            h('p', { className: 'dshtunnel-subtitle' }, t('subtitle')),
          ),
          h('span', { className: `dshtunnel-badge ${tone}` }, h('span', { className: 'dshtunnel-dot' }), badge),
        ),

        h(
          'section',
          { className: 'dshtunnel-card dshtunnel-hero', key: 'hero' },
          h(
            'div',
            { className: 'dshtunnel-hero-copy' },
            h('div', { className: 'dshtunnel-eyebrow' }, t('connection')),
            h('div', { className: 'dshtunnel-hero-line' }, h('span', { className: `dshtunnel-orb ${tone}` }), status),
            h(
              'p',
              { className: 'dshtunnel-muted' },
              connected
                ? t('proxyHint')
                : phase === 'error' && snapshot.lastError
                  ? snapshot.lastError
                  : nodes.length === 0
                    ? t('startHint')
                    : t('directHint'),
            ),
            h(
              'div',
              { className: 'dshtunnel-facts' },
              h(Fact, { key: 'endpoint', label: t('endpoint'), value: connected && snapshot.port ? `127.0.0.1:${snapshot.port}` : '—' }),
              h(Fact, { key: 'exit', label: t('exitIp'), value: snapshot.exitIp || '—' }),
              h(Fact, { key: 'core', label: t('coreVersion'), value: snapshot.coreVersion || '—' }),
            ),
          ),
          h(
            'div',
            { className: 'dshtunnel-hero-actions' },
            connected
              ? h(
                  'button',
                  { type: 'button', className: 'dshtunnel-btn danger', disabled: working, onClick: disconnect },
                  busy === 'disconnect' ? t('stopping') : t('disconnect'),
                )
              : h(
                  'button',
                  {
                    type: 'button',
                    className: 'dshtunnel-btn primary',
                    disabled: working || nodes.length === 0,
                    onClick: connect,
                  },
                  busy === 'connect' ? t('connecting') : t('connect'),
                ),
            h(
              'button',
              { type: 'button', className: 'dshtunnel-btn', disabled: working || !connected, onClick: testExit },
              busy === 'test' ? t('testingExit') : t('testExit'),
            ),
          ),
        ),

        error
          ? h(
              'div',
              { className: 'dshtunnel-alert error', key: 'error' },
              h('span', null, h('b', null, `${t('errorTitle')}: `), error),
              h('button', { type: 'button', onClick: () => setError(''), 'aria-label': t('dismiss') }, '×'),
            )
          : null,
        notice
          ? h(
              'div',
              { className: 'dshtunnel-alert notice', key: 'notice' },
              h('span', null, h('b', null, `${t('noticeTitle')}: `), notice),
              h('button', { type: 'button', onClick: () => setNotice(''), 'aria-label': t('dismiss') }, '×'),
            )
          : null,

        h(
          'section',
          { className: 'dshtunnel-card', key: 'subscription' },
          h(
            'div',
            { className: 'dshtunnel-card-head' },
            h(
              'div',
              null,
              h('h2', null, t('subscriptionTitle')),
              h('p', null, t(inputMode === 'yaml' ? 'yamlHint' : 'subscriptionHint')),
            ),
          ),
          h('div', { style: { display: 'flex', gap: 8, marginBottom: 12 } },
            ...['url', 'yaml'].map((mode) => h('button', {
              key: mode, type: 'button', 'aria-pressed': inputMode === mode,
              className: `dshtunnel-btn${inputMode === mode ? ' primary' : ''}`,
              disabled: working, onClick: () => setInputMode(mode),
            }, t(mode === 'yaml' ? 'yamlMode' : 'urlMode')))),
          inputMode === 'yaml' ? h('div', null,
            h('textarea', {
              className: 'dshtunnel-input', rows: 12,
              style: { width: '100%', height: 240, padding: 12, resize: 'vertical', fontFamily: 'monospace' },
              'aria-label': t('yamlMode'), placeholder: t('yamlPlaceholder'),
              spellCheck: false, autoComplete: 'off', value: yamlDraft,
              disabled: connected || working, onChange: (event) => setYamlDraft(event.target.value),
            }),
            h('p', { className: 'dshtunnel-muted' }, t('yamlPrivacy')),
            h('button', { type: 'button', className: 'dshtunnel-btn primary',
              style: { marginTop: 10 }, disabled: connected || working || !yamlDraft.trim(),
              onClick: importYaml,
            }, t(busy === 'import' ? 'importing' : 'importYaml')),
          ) : h(
            'div',
            { className: 'dshtunnel-inputrow' },
            h('input', {
              className: 'dshtunnel-input',
              type: 'url',
              inputMode: 'url',
              autoComplete: 'off',
              spellCheck: false,
              placeholder: t('subscriptionPlaceholder'),
              value: urlDraft,
              disabled: connected || working,
              onChange: (event) => setUrlDraft(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter') saveSubscription();
              },
            }),
            h(
              'button',
              {
                type: 'button',
                className: 'dshtunnel-btn primary',
                disabled: connected || working || urlDraft.trim() === '',
                onClick: saveSubscription,
              },
              busy === 'subscribe' ? t('updating') : t('saveSubscription'),
            ),
          ),
          h(
            'div',
            { className: 'dshtunnel-meta' },
            h('span', null, h('b', null, String(snapshot.subscription.nodeCount)), ` ${t('nodes')}`),
            snapshot.subscription.updatedAt
              ? h('span', null, `${t('updatedAt')} `, h('b', null, formatDate(snapshot.subscription.updatedAt)))
              : null,
            userinfo?.expire ? h('span', null, `${t('expiresAt')} `, h('b', null, formatExpiry(userinfo.expire))) : null,
            h('span', null, `${t('traffic')} `, h('b', null, traffic)),
            snapshot.subscription.nodeCount > 0 && !connected
              ? h(
                  'button',
                  { type: 'button', className: 'dshtunnel-btn link', disabled: working, onClick: clearSubscription },
                  t('clearSubscription'),
                )
              : null,
          ),
          h(
            'div',
            { className: 'dshtunnel-meta dshtunnel-allowinsecure' },
            h('label', { className: 'dshtunnel-switch' },
              h('input', {
                type: 'checkbox',
                checked: snapshot.subscription.allowInsecure === true,
                disabled: connected || working,
                onChange: (event) => toggleAllowInsecure(event.target.checked),
              }),
              h('span', { className: 'dshtunnel-switch-label' }, t('allowInsecure')),
            ),
            h('span', { className: 'dshtunnel-muted' }, t('allowInsecureHint')),
          ),
          snapshot.subscription.warnings?.length
            ? h(
                'div',
                { className: 'dshtunnel-warn' },
                snapshot.subscription.warnings.map((warning) => h('div', { key: warning }, warning)),
              )
            : null,
          !snapshot.coreAvailable
            ? h('div', { className: 'dshtunnel-meta' }, h('span', null, t('firstRunNote')))
            : null,
        ),

        h(
          'section',
          { className: 'dshtunnel-card', key: 'nodes' },
          h(
            'div',
            { className: 'dshtunnel-card-head' },
            h('div', null, h('h2', null, t('nodeTitle')), h('p', null, t('nodeHint'))),
            nodes.length > 0
              ? h(
                  'button',
                  {
                    type: 'button',
                    className: 'dshtunnel-btn',
                    disabled: working || !connected,
                    onClick: latencyAll,
                  },
                  busy === 'latency:all' ? t('testing') : t('testAll'),
                )
              : null,
          ),
          nodes.length === 0
            ? h(
                'div',
                { className: 'dshtunnel-empty' },
                h('strong', null, t('noNodes')),
                h('p', null, t('noNodesHint')),
                h(
                  'div',
                  { className: 'dshtunnel-steps' },
                  [t('firstStep'), t('secondStep'), t('thirdStep')].map((label, index) =>
                    h('span', { className: 'dshtunnel-step', key: label }, h('i', null, String(index + 1)), label),
                  ),
                ),
              )
            : h(
                'div',
                null,
                h('input', {
                  className: 'dshtunnel-input',
                  type: 'search',
                  placeholder: t('searchPlaceholder'),
                  value: filter,
                  onChange: (event) => setFilter(event.target.value),
                  'aria-label': t('searchPlaceholder'),
                }),
                h(
                  'div',
                  { className: 'dshtunnel-list' },
                  visibleNodes.map((node) =>
                    h(
                      'button',
                      {
                        type: 'button',
                        key: node.name,
                        className: `dshtunnel-node${node.name === snapshot.selected ? ' selected' : ''}`,
                        disabled: working,
                        onClick: () => selectNode(node),
                        onDoubleClick: () => latencyOne(node),
                        title: `${node.name} — ${t('selectNode')}`,
                        'aria-pressed': node.name === snapshot.selected,
                      },
                      h('span', { className: 'dshtunnel-radio' }),
                      h('span', { className: 'dshtunnel-node-name' }, node.name),
                      h('span', { className: 'dshtunnel-type' }, node.type),
                      node.insecure
                        ? h('span', { className: 'dshtunnel-insecure', title: t('insecureNode') }, '!')
                        : null,
                      h(
                        'span',
                        { className: `dshtunnel-delay ${delayClass(delays[node.name])}` },
                        busy === `latency:${node.name}` ? '…' : renderDelay(node.name),
                      ),
                    ),
                  ),
                ),
              ),
        ),

        h(
          'section',
          { className: 'dshtunnel-card', key: 'direct' },
          h(
            'div',
            { className: 'dshtunnel-card-head' },
            h(
              'div',
              null,
              h('h2', null, t('directListTitle')),
              h('p', null, t('directListHint')),
            ),
          ),
          h(
            'div',
            { className: 'dshtunnel-inputrow' },
            h('input', {
              className: 'dshtunnel-input',
              type: 'text',
              autoComplete: 'off',
              spellCheck: false,
              placeholder: t('directPlaceholder'),
              value: directDraft,
              disabled: connected || working,
              onChange: (event) => setDirectDraft(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter') addDirectHost();
              },
            }),
            h(
              'button',
              {
                type: 'button',
                className: 'dshtunnel-btn primary',
                disabled: connected || working || directDraft.trim() === '',
                onClick: addDirectHost,
              },
              busy === 'direct' ? t('updating') : t('directAdd'),
            ),
          ),
          (snapshot.directHosts ?? []).length === 0
            ? h('p', { className: 'dshtunnel-muted' }, t('directEmpty'))
            : h(
                'div',
                { className: 'dshtunnel-meta dshtunnel-directlist' },
                ...(snapshot.directHosts ?? []).map((entry) =>
                  h(
                    'span',
                    { className: 'dshtunnel-step', key: entry },
                    h('code', null, entry),
                    h(
                      'button',
                      {
                        type: 'button',
                        className: 'dshtunnel-btn link',
                        disabled: connected || working,
                        onClick: () => removeDirectHost(entry),
                        'aria-label': t('directRemove'),
                      },
                      '×',
                    ),
                  ),
                ),
              ),
          h('p', { className: 'dshtunnel-muted' }, t('directNote')),
        ),

        h(
          'div',
          { className: 'dshtunnel-scope', key: 'scope' },
          h(
            'svg',
            { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true },
            h('path', { d: 'M12 3.5 5.5 6v5.4c0 4.1 2.7 7.7 6.5 9.1 3.8-1.4 6.5-5 6.5-9.1V6L12 3.5Z', stroke: 'var(--dsw-alias-label-secondary)', strokeWidth: 1.6, strokeLinejoin: 'round' }),
            h('path', { d: 'm9.2 12 1.9 1.9 3.8-4.2', stroke: 'var(--dsw-alias-state-success-primary)', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round' }),
          ),
          h(
            'div',
            null,
            h('strong', null, t('scopeTitle')),
            h('p', null, t('scopeBody')),
            h('p', null, t('securityNote')),
          ),
        ),
      ]);
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(
          () =>
            ctx.locale.register(NS, {
              en,
              zh,
            }),
          'tunnel: dictionaries',
        );
        const t = ctx.locale.bind(NS);
        ctx.effect(
          () =>
            ctx.slots.inject('settings.section', () =>
              ctx.slots.register(
                {
                  name: 'settings.section',
                  id: 'tunnel-connect',
                  order: 17,
                  label: () => t('nav'),
                  locale: NS,
                  inject: () => ({
                    locale: {
                      get: () => ctx.locale.getSnapshot(),
                      subscribe: (listener) => ctx.locale.subscribe(listener),
                    },
                  }),
                },
                Section,
              ),
            ),
          'tunnel: settings section',
        );
      },
    };
  },
});
