
const fs = require('fs');
const path = require('path');
const acme = require('acme-client');

const BASE = process.env.KATABUMP_BASE || __dirname;
const config = JSON.parse(
  fs.readFileSync(path.join(BASE, 'ssl-config.json'), 'utf8')
);

const DOMAIN = config.domain;
const ZONE_ID = config.zoneId;
const TOKEN = config.apiToken;
const CERT_DIR = path.join(BASE, 'cert');

fs.mkdirSync(CERT_DIR, { recursive: true });

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

async function cfApi(method, endpoint, body) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4${endpoint}`,
    {
      method,
      headers: {
        Authorization: `Bearer ${TOKEN}`,
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

async function main() {
  if (fs.existsSync(path.join(CERT_DIR, 'privkey.pem')) || fs.existsSync(path.join(CERT_DIR, 'fullchain.pem'))) {
    throw new Error('Certificate files already exist; use npm start for automatic certificate renewal.');
  }
  if (!config.email || !ZONE_ID || !TOKEN) {
    throw new Error('请先完善 ssl-config.json');
  }

  if (!DOMAIN || DOMAIN === 'example.com') {
    throw new Error('请检查申请域名');
  }

  // 检查 Cloudflare API 权限
  const zone = await cfApi('GET', `/zones/${ZONE_ID}`);
  if (!(DOMAIN === zone.name || DOMAIN.endsWith('.' + zone.name)) || zone.status !== 'active') {
    throw new Error('Cloudflare Zone 不匹配或尚未激活');
  }

  console.log('Cloudflare API 验证成功');

  // 保留 ACME 账户密钥
  const accountPath = path.join(CERT_DIR, 'account.pem');
  let accountKey;

  if (fs.existsSync(accountPath)) {
    accountKey = fs.readFileSync(accountPath);
  } else {
    accountKey = await acme.crypto.createPrivateKey();
    fs.writeFileSync(accountPath, accountKey, { mode: 0o600 });
  }

  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey
  });

  const [privateKey, csr] = await acme.crypto.createCsr({
    altNames: [DOMAIN, `*.${DOMAIN}`]
  });

  const records = new Map();

  const cert = await client.auto({
    csr,
    email: config.email,
    termsOfServiceAgreed: true,
    challengePriority: ['dns-01'],

    challengeCreateFn: async (authz, challenge, value) => {
      const name = `_acme-challenge.${DOMAIN}`;

      const record = await cfApi(
        'POST',
        `/zones/${ZONE_ID}/dns_records`,
        {
          type: 'TXT',
          name,
          content: value,
          ttl: 60
        }
      );

      records.set(challenge.token, record.id);

      console.log('已创建 DNS-01 验证记录');
      console.log('等待 DNS 传播...');
      await sleep(45000);
    },

    challengeRemoveFn: async (authz, challenge) => {
      const id = records.get(challenge.token);
      if (!id) return;

      await cfApi(
        'DELETE',
        `/zones/${ZONE_ID}/dns_records/${id}`
      );

      records.delete(challenge.token);
      console.log('已清理验证记录');
    }
  });

  fs.writeFileSync(
    path.join(CERT_DIR, 'privkey.pem'),
    privateKey,
    { mode: 0o600 }
  );

  fs.writeFileSync(
    path.join(CERT_DIR, 'fullchain.pem'),
    cert,
    { mode: 0o600 }
  );

  console.log('证书申请成功！');
  console.log('已保存到:', CERT_DIR);
}

main().catch(err => {
  console.error('证书申请失败：', err.message);
  process.exitCode = 1;
});
