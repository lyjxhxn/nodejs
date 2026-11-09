# KataBump Node.js 节点

从 KataBump 节点项目整理的独立版本，提供 VLESS、VMess、Trojan 的 TLS + WebSocket 入口和私密订阅。

**不包含服务器自动续期功能**，不会读取 KataBump Cookie、CSRF 或调用面板续期接口。服务器到期时间需要自行管理。TLS 证书自动续签仍保留，用来维持 HTTPS/WSS 连接。

## 环境

- Linux 服务器或 KataBump Node.js 容器，Node.js 22 或更高版本。
- 与服务器 CPU 架构匹配的 sing-box 可执行文件。
- 一个由 Cloudflare 管理 DNS 的域名，以及对应 Zone 的 API Token（Zone DNS 编辑、Zone 读取权限）。
- 可写、持久保存的项目目录和一个已开放的 TCP 端口。

仓库不包含 sing-box 二进制文件、真实账号配置、节点凭据、订阅令牌或证书私钥。

## 首次安装

```sh
git clone https://github.com/lyjxhxn/nodejs.git
cd nodejs
npm ci --omit=dev
npm run init
```

初始化会随机生成节点 UUID 和 Trojan 密码，写入 `singbox/config.json`，并创建 `ssl-config.json`。重复运行不会覆盖已有配置。初始化脚本不会输出凭据。

从 sing-box 官方发行页面下载对应 Linux 架构的版本，将解压后的可执行文件放到 `singbox/sing-box`：

https://github.com/SagerNet/sing-box/releases

```sh
chmod 700 singbox/sing-box
chmod 600 ssl-config.json singbox/config.json
./singbox/sing-box version
./singbox/sing-box check -c singbox/config.json
```

以配置检查通过为准；内网三个入站必须保持 `127.0.0.1`，不要在面板额外开放它们。

## 域名与证书

在服务器上编辑 `ssl-config.json`：

| 字段 | 填写内容 |
| --- | --- |
| `domain` | 节点域名，如 `node.example.com` |
| `zoneId` | 管理该域名的 Cloudflare Zone ID |
| `apiToken` | 该 Zone 的 Cloudflare API Token |
| `email` | ACME 联系邮箱 |

将域名的 A/AAAA 记录指向服务器可达地址，使用“仅 DNS”（灰云）；删除不可达的 AAAA 记录。面板开放的公网端口需要转发到 Node.js 监听端口。

```sh
npm run cert
```

该命令通过 Cloudflare DNS-01 申请域名及其通配符证书，执行表示同意 Let's Encrypt 服务条款。需要等待 DNS 传播。已有证书时该命令会拒绝覆盖；正常运行中的证书续签由主程序处理。

## 启动与端口

默认监听 TCP `20234`：

```sh
npm start
```

面板启动命令可以填写 `node index.js`，工作目录设置为项目所在目录。首次启动前必须完成依赖安装、配置填写、sing-box 安装和证书申请。

公网端口与容器内监听端口不同时，通过环境变量分别设置：

```sh
SERVER_PORT=20234 PUBLIC_PORT=30538 npm start
```

`SERVER_PORT` 是内部监听端口；`PUBLIC_PORT` 用于生成客户端链接，未设置时与监听端口相同。面板环境变量也可直接填写这两个值。

程序默认从项目目录读取配置。可选 `KATABUMP_BASE` 指定独立的数据目录；此时私密配置、`cert/`、订阅文件及 `singbox/`（包括可执行文件）都应放在该目录。

## 客户端使用

启动后，在服务器文件管理器中打开 `subscription-url.txt`，将其中的 Base64 订阅地址导入支持对应协议的客户端。也可以从 `nodes.txt` 单独导入节点。

| 协议 | WebSocket 路径 | 内部端口 |
| --- | --- | --- |
| VLESS | `/vless` | 10003 |
| VMess | `/sb` | 10001 |
| Trojan | `/trojan` | 10002 |

客户端启用 TLS，SNI 和 Host 使用配置的域名。订阅 URL 中的令牌等同访问凭据，不能公开分享。

## 更新与故障排查

- 更新代码时保留 `ssl-config.json`、`singbox/config.json`、`cert/` 和 `subscription-token.txt`；不要用示例配置覆盖它们。
- 执行 `npm ci --omit=dev` 后重启 Node.js。证书在启动时及每 12 小时检查一次，剩余 30 天以内尝试续签；失败有至少 6 小时冷却，下一次定时检查再试。
- `ENOENT`：检查配置、证书、二进制路径；首次运行先完成初始化和证书申请。
- sing-box 启动失败：检查文件架构、执行权限和配置检查结果。HTTPS 首页可访问不代表代理内核已经正常运行。
- 客户端连接失败：核对 DNS、面板端口映射、`PUBLIC_PORT`、TLS 域名及 WS 路径。

## 不提交的文件

`.gitignore` 已排除真实配置、证书、私钥、订阅文件、运行日志、压缩备份及依赖目录。仓库只保存代码和空白示例；不要使用 `git add -f` 强制提交私密文件。旧项目的服务器续期脚本和数据不属于本仓库。
