
'use strict';

const https = require('node:https');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const tls = require('node:tls');
const net = require('node:net');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');

const WebSocket = require('ws');
const acme = require('acme-client');

// ==============================
// 1. 基础配置
// ==============================

const BASE = process.env.KATABUMP_BASE || __dirname;
const CERT_DIR = path.join(BASE, 'cert');

const CONFIG_PATH = path.join(BASE, 'ssl-config.json');

const CERT_PATH = path.join(CERT_DIR, 'fullchain.pem');
const KEY_PATH = path.join(CERT_DIR, 'privkey.pem');
const ACCOUNT_PATH = path.join(CERT_DIR, 'account.pem');
const STATE_PATH = path.join(CERT_DIR, 'renewal-state.json');

const PORT = Number(process.env.SERVER_PORT || 20234);


const CHECK_MS = 12 * 60 * 60 * 1000;
const RENEW_BEFORE_MS = 30 * 86400000;
const RETRY_MS = 6 * 60 * 60 * 1000;

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

const config = JSON.parse(
  fs.readFileSync(CONFIG_PATH, 'utf8')
);
const DOMAIN = config.domain;
const PUBLIC_PORT = Number(process.env.PUBLIC_PORT || PORT);
for (const port of [PORT, PUBLIC_PORT]) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
}

if (
  !DOMAIN || DOMAIN === 'example.com' ||
  !config.zoneId ||
  !config.apiToken ||
  !config.email
) {
  throw new Error('ssl-config.json 配置不完整');
}

// 原 VLESS UUID 保存在 vless-config.json，迁移脚本会读取它，
// 运行时所有节点身份信息直接来自 singbox/config.json。

// ==============================
// 2. Cloudflare API
// ==============================

async function cfApi(method, endpoint, body) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4${endpoint}`,
    {
      method,
      headers: {
        Authorization: `Bearer ${config.apiToken}`,
        'Content-Type': 'application/json'
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20000)
    }
  );

  const data = await response.json();

  if (!response.ok || !data.success) {
    throw new Error(
      `Cloudflare API 失败: ${JSON.stringify(data.errors)}`
    );
  }

  return data.result;
}

// ==============================
// 3. 证书检查与续期
// ==============================

function getExpiry(pem) {
  const cert = new crypto.X509Certificate(pem);
  const san = cert.subjectAltName || '';

  if (
    !san.includes(`DNS:${DOMAIN}`) ||
    !san.includes(`DNS:*.${DOMAIN}`)
  ) {
    throw new Error('证书域名不匹配');
  }

  return new Date(cert.validTo).getTime();
}

async function writeAtomic(file, content) {
  const tmp = `${file}.${process.pid}.tmp`;

  await fsp.writeFile(tmp, content, { mode: 0o600 });
  await fsp.rename(tmp, file);
}

async function readState() {
  try {
    return JSON.parse(
      await fsp.readFile(STATE_PATH, 'utf8')
    );
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

async function writeState(state) {
  await writeAtomic(
    STATE_PATH,
    JSON.stringify(state, null, 2)
  );
}

let renewing = false;
let server;

async function renewCertificate() {
  if (renewing) return;

  renewing = true;

  try {
    const oldCert = await fsp.readFile(CERT_PATH, 'utf8');
    const expiry = getExpiry(oldCert);

    const days = Math.ceil(
      (expiry - Date.now()) / 86400000
    );

    console.log(`证书剩余约 ${days} 天`);

    if (expiry - Date.now() > RENEW_BEFORE_MS) {
      return;
    }

    const state = await readState();

    if (
      state.nextAttempt &&
      Date.now() < state.nextAttempt
    ) {
      console.log('续期冷却中，稍后重试');
      return;
    }

    await writeState({
      nextAttempt: Date.now() + RETRY_MS
    });

    console.log('开始续期证书');

    const zone = await cfApi(
      'GET',
      `/zones/${config.zoneId}`
    );

    if (
      !(DOMAIN === zone.name || DOMAIN.endsWith('.' + zone.name)) ||
      zone.status !== 'active'
    ) {
      throw new Error('Cloudflare Zone 校验失败');
    }

    let accountKey;

    try {
      accountKey = await fsp.readFile(ACCOUNT_PATH);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;

      accountKey = await acme.crypto.createPrivateKey();
      await writeAtomic(ACCOUNT_PATH, accountKey);
    }

    const client = new acme.Client({
      directoryUrl: acme.directory.letsencrypt.production,
      accountKey
    });

    const [newKey, csr] = await acme.crypto.createCsr({
      altNames: [
        DOMAIN,
        `*.${DOMAIN}`
      ]
    });

    const records = new Map();

    const newCert = await client.auto({
      csr,
      email: config.email,
      termsOfServiceAgreed: true,
      challengePriority: ['dns-01'],

      challengeCreateFn: async (_authz, challenge, value) => {
        const record = await cfApi(
          'POST',
          `/zones/${config.zoneId}/dns_records`,
          {
            type: 'TXT',
            name: `_acme-challenge.${DOMAIN}`,
            content: value,
            ttl: 60
          }
        );

        records.set(challenge.token, record.id);

        console.log('已创建 DNS 验证记录');
        await sleep(60000);
      },

      challengeRemoveFn: async (_authz, challenge) => {
        const id = records.get(challenge.token);

        if (!id) return;

        try {
          await cfApi(
            'DELETE',
            `/zones/${config.zoneId}/dns_records/${id}`
          );
        } catch (err) {
          console.error('TXT 清理失败:', err.message);
        }

        records.delete(challenge.token);
      }
    });

    const newExpiry = getExpiry(newCert);

    if (newExpiry <= Date.now()) {
      throw new Error('新证书无效');
    }

    tls.createSecureContext({
      key: newKey,
      cert: newCert
    });

    const oldKey = await fsp.readFile(KEY_PATH);

    await writeAtomic(
      path.join(CERT_DIR, 'privkey.previous.pem'),
      oldKey
    );

    await writeAtomic(
      path.join(CERT_DIR, 'fullchain.previous.pem'),
      oldCert
    );

    await writeAtomic(KEY_PATH, newKey);
    await writeAtomic(CERT_PATH, newCert);

    server.setSecureContext({
      key: newKey,
      cert: newCert
    });

    await writeState({
      nextAttempt: 0,
      lastSuccess: Date.now()
    });

    console.log(
      '证书续期成功，有效期至:',
      new Date(newExpiry).toISOString()
    );

  } catch (err) {
    console.error('证书续期失败:', err.message);
  } finally {
    renewing = false;
  }
}

// ==============================
// 4-6. 代理协议均迁移至 sing-box。
// Node.js 不再解析任何 VLESS/VMess/Trojan 数据。
// ==============================

// ==============================
// 7. HTTPS + WSS
// ==============================

server = https.createServer({
  key: fs.readFileSync(KEY_PATH),
  cert: fs.readFileSync(CERT_PATH)
}, (req, res) => {
  let pathname;
  try {
    pathname = new URL(req.url, 'https://localhost').pathname;
  } catch {
    res.writeHead(400);
    res.end();
    return;
  }

  const noCacheHeaders = {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  };

  // 订阅属于敏感凭证，只允许访问持有随机令牌的私密路径。
  if (pathname === `/sub/${SUB_TOKEN}` || pathname === `/nodes/${SUB_TOKEN}`) {
    try {
      const { nodes, encoded } = exportNodeFiles();
      res.writeHead(200, noCacheHeaders);
      res.end(pathname.startsWith('/sub/') ? encoded : nodes);
    } catch (err) {
      console.error('[nodes] 订阅生成失败:', err.message);
      res.writeHead(503, noCacheHeaders);
      res.end('订阅暂时不可用，请检查 sing-box 配置');
    }
    return;
  }

  if (pathname !== '/') {
    res.writeHead(404, noCacheHeaders);
    res.end('Not Found');
    return;
  }

  res.writeHead(200, noCacheHeaders);
  res.end('HTTPS + WSS 三协议入口运行正常！代理协议由 sing-box 处理。');
});

const testWss = new WebSocket.Server({
  noServer: true,
  perMessageDeflate: false
});

testWss.on('connection', ws => {
  ws.send('WSS 连接成功！');

  ws.on('message', msg => {
    ws.send('服务器收到：' + msg.toString());
  });
});

// ==============================
// 7A. sing-box 内网 WS 转发 + 子进程管理
//     /vless, /sb, /trojan → 本机 10003/10001/10002
// ==============================

const SINGBOX_DIR = path.join(BASE, 'singbox');
const SINGBOX_BIN = path.join(SINGBOX_DIR, 'sing-box');
const SINGBOX_CONFIG = path.join(SINGBOX_DIR, 'config.json');
const SINGBOX_LOCAL_VLESS_PORT = 10003;
const SINGBOX_LOCAL_PORT = 10001;
const SINGBOX_LOCAL_TROJAN_PORT = 10002;
const SINGBOX_WS_ROUTES = new Map([
  ['/vless', SINGBOX_LOCAL_VLESS_PORT],
  ['/sb', SINGBOX_LOCAL_PORT],
  ['/trojan', SINGBOX_LOCAL_TROJAN_PORT]
]);

// 自动生成本地节点清单及带令牌的在线订阅。
// 只从实际配置读取 UUID/密码，不把私密链接打印到运行日志。
const SUB_TOKEN_FILE = path.join(BASE, 'subscription-token.txt');
const NODE_LIST_FILE = path.join(BASE, 'nodes.txt');
const SUB_FILE = path.join(BASE, 'sub.txt');
const SUB_URL_FILE = path.join(BASE, 'subscription-url.txt');

function writePrivateFile(file, content) {
  fs.writeFileSync(file, content, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function getSubscriptionToken() {
  if (fs.existsSync(SUB_TOKEN_FILE)) {
    const token = fs.readFileSync(SUB_TOKEN_FILE, 'utf8').trim();
    if (!/^[a-f0-9]{48,128}$/.test(token)) {
      throw new Error('subscription-token.txt 格式有误，请检查私密订阅令牌');
    }
    fs.chmodSync(SUB_TOKEN_FILE, 0o600);
    return token;
  }
  const token = crypto.randomBytes(32).toString('hex');
  writePrivateFile(SUB_TOKEN_FILE, token + '\n');
  return token;
}

const SUB_TOKEN = getSubscriptionToken();

function generateNodeLinks() {
  const nodes = [];
  const ws = (pathName) => encodeURIComponent(pathName);
  const host = DOMAIN;
  const port = PUBLIC_PORT;
  const vlessName = encodeURIComponent('FR-KataBump-VLESS-WS');
  if (!fs.existsSync(SINGBOX_CONFIG)) throw new Error('找不到 sing-box 配置，无法生成实际节点');
  {
    const cfg = JSON.parse(fs.readFileSync(SINGBOX_CONFIG, 'utf8'));
    if (!Array.isArray(cfg.inbounds)) throw new Error('sing-box 配置缺少 inbounds');

    const findInbound = (type, pathName, listenPort) => cfg.inbounds.find(x =>
      x.type === type && x.transport?.type === 'ws' &&
      x.transport.path === pathName && x.listen === '127.0.0.1' &&
      Number(x.listen_port) === listenPort
    );

    const vless = findInbound('vless', '/vless', SINGBOX_LOCAL_VLESS_PORT);
    if (!vless) throw new Error('未找到 sing-box VLESS /vless:10003 入站，请先运行 npm run init');
    const vlessUUID = vless.users?.[0]?.uuid;
    if (typeof vlessUUID !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(vlessUUID)) {
      throw new Error('sing-box VLESS UUID 缺失或格式错误');
    }
    nodes.push(`vless://${vlessUUID}@${host}:${port}?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=${ws('/vless')}#${vlessName}`);

    const vmess = findInbound('vmess', '/sb', SINGBOX_LOCAL_PORT);
    if (!vmess) throw new Error('VMess /sb:10001 入站缺失');
    {
      const uuid = vmess.users?.[0]?.uuid;
      if (!/^[a-f0-9-]{36}$/i.test(uuid || '')) {
        throw new Error('VMess UUID 缺失或格式错误');
      }
      const payload = {
        v: '2', ps: 'FR-KataBump-VMess-WS', add: host, port: String(port),
        id: uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none',
        host, path: '/sb', tls: 'tls', sni: host
      };
      nodes.push('vmess://' + Buffer.from(JSON.stringify(payload)).toString('base64'));
    }

    const trojan = findInbound('trojan', '/trojan', SINGBOX_LOCAL_TROJAN_PORT);
    if (!trojan) throw new Error('Trojan /trojan:10002 入站缺失');
    {
      const password = trojan.users?.[0]?.password;
      if (typeof password !== 'string' || password.length < 16) {
        throw new Error('Trojan 密码缺失或过短');
      }
      nodes.push(`trojan://${encodeURIComponent(password)}@${host}:${port}?security=tls&sni=${host}&type=ws&host=${host}&path=${ws('/trojan')}#${encodeURIComponent('FR-KataBump-Trojan-WS')}`);
    }
  }

  return nodes;
}

function exportNodeFiles() {
  const links = generateNodeLinks();
  const nodes = links.join('\n') + '\n';
  const encoded = Buffer.from(nodes, 'utf8').toString('base64') + '\n';
  writePrivateFile(NODE_LIST_FILE, nodes);
  writePrivateFile(SUB_FILE, encoded);
  writePrivateFile(
    SUB_URL_FILE,
    `节点明文: https://${DOMAIN}:${PUBLIC_PORT}/nodes/${SUB_TOKEN}\n` +
    `Base64 订阅: https://${DOMAIN}:${PUBLIC_PORT}/sub/${SUB_TOKEN}\n`
  );
  return { nodes, encoded, count: links.length };
}

const SINGBOX_RESTART_DELAY = 15000;
const SINGBOX_MAX_RESTARTS = 3;
let singboxProcess = null;
let singboxRestartTimer = null;
let singboxRestartCount = 0;
let singboxStopping = false;

function startSingBox() {
  if (singboxStopping || process.env.SINGBOX_ENABLED === 'false') {
    console.log('[sing-box] 已通过环境变量关闭');
    return;
  }

  if (!fs.existsSync(SINGBOX_BIN) || !fs.existsSync(SINGBOX_CONFIG)) {
    console.error('[sing-box] 未找到程序或配置，代理节点将不可用');
    return;
  }

  // Node.js 的 HTTPS 服务可独立运行；sing-box 退出时三种代理都会受影响。
  let startedAt = Date.now();
  const child = spawn(SINGBOX_BIN, ['run', '-c', SINGBOX_CONFIG], {
    cwd: SINGBOX_DIR,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  singboxProcess = child;

  child.stdout.on('data', data => {
    process.stdout.write('[sing-box] ' + data.toString());
  });
  child.stderr.on('data', data => {
    process.stderr.write('[sing-box] ' + data.toString());
  });
  child.on('spawn', () => {
    console.log('[sing-box] 进程已启动 PID:', child.pid);
  });
  child.on('error', err => {
    console.error('[sing-box] 启动错误:', err.message);
  });
  child.on('close', (code, signal) => {
    if (singboxProcess !== child) return;
    singboxProcess = null;
    if (singboxStopping) return;

    console.error(`[sing-box] 已退出：code=${code}, signal=${signal}`);
    if (Date.now() - startedAt > 60000) singboxRestartCount = 0;
    if (singboxRestartCount >= SINGBOX_MAX_RESTARTS) {
      console.error('[sing-box] 连续异常退出，停止自动重试；三种代理服务将不可用');
      return;
    }
    singboxRestartCount++;
    singboxRestartTimer = setTimeout(startSingBox, SINGBOX_RESTART_DELAY);
    singboxRestartTimer.unref();
  });
}

// 直接透传 HTTP/1.1 WebSocket Upgrade 到本机 sing-box。
// TLS 已由外层 Node.js 终止，sing-box 内部只需要明文 WS。
function proxySingBoxUpgrade(req, client, head, backendPort) {
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  const connection = String(req.headers.connection || '').toLowerCase();
  if (req.method !== 'GET' || upgrade !== 'websocket' ||
      !connection.split(',').some(item => item.trim() === 'upgrade') ||
      !req.headers['sec-websocket-key']) {
    client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  const backend = net.connect({ host: '127.0.0.1', port: backendPort });
  let connected = false;
  const timer = setTimeout(() => backend.destroy(new Error('Backend connect timeout')), 10000);
  timer.unref();

  backend.once('connect', () => {
    connected = true;
    clearTimeout(timer);
    if (client.destroyed) return backend.destroy();

    // 使用原始升级请求头，保留 Upgrade、Connection、Sec-WebSocket-Key 等。
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    backend.write(lines.join('\r\n') + '\r\n\r\n', 'latin1');
    if (head && head.length) backend.write(head);
    client.pipe(backend);
    backend.pipe(client);
  });

  backend.on('error', err => {
    clearTimeout(timer);
    console.error(`[sing-box] ${req.url} 转发失败:`, err.message);
    if (client.destroyed) return;
    if (!connected) {
      client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    } else {
      client.destroy();
    }
  });
  backend.on('close', () => {
    clearTimeout(timer);
    if (connected && !client.destroyed) client.destroy();
  });
  client.on('close', () => backend.destroy());
  client.on('error', () => backend.destroy());
}

function stopSingBox() {
  singboxStopping = true;
  if (singboxRestartTimer) clearTimeout(singboxRestartTimer);
  if (singboxProcess && !singboxProcess.killed) {
    singboxProcess.kill('SIGTERM');
  }
}

server.on('upgrade', (req, socket, head) => {
  let pathname;

  try {
    pathname = new URL(
      req.url,
      'https://localhost'
    ).pathname;
  } catch {
    socket.destroy();
    return;
  }

  if (SINGBOX_WS_ROUTES.has(pathname)) {
    proxySingBoxUpgrade(req, socket, head, SINGBOX_WS_ROUTES.get(pathname));
    return;
  }

  const target = pathname === '/ws-test' ? testWss : null;

  if (!target) {
    socket.destroy();
    return;
  }

  target.handleUpgrade(req, socket, head, ws => {
    target.emit('connection', ws, req);
  });
});

// ==============================
// 8. 启动
// ==============================

server.on('error', err => {
  console.error('服务器错误:', err.message);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('KataBump sing-box 三协议 WSS 入口已启动');
  console.log('域名:', DOMAIN);
  console.log('端口:', PORT);
  console.log('sing-box VLESS 路径: /vless → 127.0.0.1:10003');
  console.log('WSS 测试路径: /ws-test');
  console.log('sing-box VMess 路径: /sb → 127.0.0.1:10001');
  console.log('sing-box Trojan 路径: /trojan → 127.0.0.1:10002');
  console.log('证书自动续期: 已启用');
  console.log('================================');

  try {
    const result = exportNodeFiles();
    console.log(`[nodes] 已生成 ${result.count} 条节点信息`);
    console.log('[nodes] 本地节点清单: nodes.txt');
    console.log('[nodes] 私密订阅地址: subscription-url.txt');
  } catch (err) {
    console.error('[nodes] 节点信息生成失败:', err.message);
  }

  startSingBox();

  void renewCertificate();

  const timer = setInterval(
    () => void renewCertificate(),
    CHECK_MS
  );

  timer.unref();
});

// 容器停止时同步清理后台进程。
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    stopSingBox();
    server.close();
    const timer = setTimeout(() => process.exit(0), 1200);
    timer.unref();
  });
}
