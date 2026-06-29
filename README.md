# Keyward

Keyward（代号 **Citadel**）是 HOLDFAST 内网的 **CA / PKI 颁发机构（internal Certificate
Authority）**，用 Rust（axum 0.8）实现。它在首次启动时生成一个**自签名 Root CA**，持久化到磁盘，
之后对内网服务签发 / 续签**叶子证书（leaf）**，并维护**证书吊销列表（CRL）**。

> Keyward 只负责**内网 PKI**。面向公网的 ACME / Let's Encrypt 证书仍然由 **Sluice** 独立处理，
> 二者互不干扰（不要把内网 CA 的逻辑塞进 Sluice 的公网 autocert）。

## 它是什么

- 默认监听 `0.0.0.0:8200`（内网端口，不对公网暴露）
- 启动时从 `CA_DIR`（默认 `/ca`）**加载或生成** Root CA：`ca.crt`（PEM，公开安全）+ `ca.key`
  （PEM，权限 `0600`）。重启后重新加载同一份材料，**CA 身份跨重启稳定** —— 所有已签发叶子证书的
  信任链不会因为重启而失效
- Root CA：ECDSA **P-384**，CA basicConstraints + keyUsage（`keyCertSign` + `cRLSign`），
  CN 来自 `CA_CN`（默认 `HOLDFAST Root CA`），长有效期（`CA_TTL_DAYS`，默认约 3650 天）
- 叶子证书：服务端生成密钥时用 ECDSA **P-256**；序列号为随机 **128-bit**；有效期受配置上限约束
  （默认 90 天，上限来自 `LEAF_TTL_DAYS`）
- 全程使用 `rcgen` crate（`ring` 后端，**不链接 OpenSSL**）完成 CA / 叶子 / CSR 签名 / CRL

## 如何运行

```bash
# 构建
cargo build

# 运行（默认内存存储 + 临时 Root CA，无需数据库 / 磁盘）
cargo run

# 测试（默认内存存储，无需数据库 —— 单元 + 契约测试全绿；
#       证书链 / EKU / CRL 吊销均用系统 openssl 实证）
cargo test
```

冒烟验证（服务运行后）：

```bash
curl -s http://127.0.0.1:8200/healthz                 # ok
curl -s http://127.0.0.1:8200/ca/root.crt             # Root CA 证书 (PEM)

# 签发一张 server 叶子证书（服务端生成密钥，便捷路径）
curl -s -X POST http://127.0.0.1:8200/ca/issue \
  -H "Authorization: Bearer $KEYWARD_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"common_name":"svc.holdfast.internal","dns_sans":["svc.holdfast.internal"],"profile":"server","ttl_hours":48}'
```

## 配置（环境变量）

所有值在对应环境变量**未设置 / 为空时保留 dev 默认**，因此内存模式开箱即用。

| 变量 | 作用 | 默认值 |
|------|------|--------|
| `BIND_ADDR` | 监听地址 | `0.0.0.0:8200` |
| `CA_DIR` | Root CA 证书 / 私钥的持久化目录（`ca.crt` + `ca.key`） | `/ca` |
| `CA_CN` | Root CA 主题 CommonName | `HOLDFAST Root CA` |
| `CA_TTL_DAYS` | Root CA 有效期（天） | `3650` |
| `LEAF_TTL_DAYS` | 叶子证书有效期上限（天），同时作为未指定 `ttl_hours` 时的默认值 | `90` |
| `KEYWARD_STORE` | 存储后端：`memory` \| `postgres` | `memory` |
| `DATABASE_URL` | Postgres DSN（仅 `postgres` 模式需要） | 无 |
| `KEYWARD_ADMIN_TOKEN` | 保护 issue / sign-csr / revoke 的 Bearer 令牌；**生产必须覆盖** | dev 默认串（须替换） |

## 端点

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/healthz` | 公开 | 存活探针 -> `200 ok` |
| GET | `/ca/root.crt` | 公开 | Root CA 证书（PEM） |
| GET | `/ca/bundle.pem` | 公开 | 完整信任链（当前单级 CA 即 Root 本身） |
| GET | `/ca/crl.pem` | 公开 | 当前 CA 签名的 CRL（含全部已吊销序列号） |
| POST | `/ca/sign-csr` | **Bearer** | 签名调用方提交的 CSR（**推荐**，请求方自留私钥） |
| POST | `/ca/issue` | **Bearer** | 服务端生成密钥并签发叶子证书（便捷） |
| POST | `/ca/revoke` | **Bearer** | 标记某序列号为已吊销 |

鉴权方式为 `Authorization: Bearer <KEYWARD_ADMIN_TOKEN>`，采用**常量时间比较**。
`root.crt` / `bundle.pem` / `crl.pem` / `healthz` 不需要鉴权（信任材料本就公开）。

### 请求 / 响应

**`POST /ca/sign-csr`**

```json
{ "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "ttl_hours": 720, "profile": "peer" }
```

`->` `{ "serial", "cert_pem", "chain_pem", "not_before", "not_after" }`（不含私钥）。

**`POST /ca/issue`**

```json
{ "common_name": "svc.internal", "dns_sans": ["svc.internal"], "ip_sans": ["10.0.0.5"],
  "ttl_hours": 720, "profile": "server" }
```

`->` `{ "serial", "cert_pem", "key_pem", "chain_pem", "not_before", "not_after" }`（含服务端生成的私钥）。

**`POST /ca/revoke`**

```json
{ "serial": "4a08d9fa...", "reason": "key_compromise" }
```

`->` `{ "serial", "revoked": true, "revoked_at" }`。未知序列号返回 `404`。

### Profile（EKU）

| profile | Extended Key Usage | 用途 |
|---------|--------------------|------|
| `server` | `serverAuth` | TLS 服务端证书 |
| `client` | `clientAuth` | TLS 客户端证书 |
| `peer` | `serverAuth` + `clientAuth` | mTLS 双向（双端都用一张证书） |

叶子证书的 `ttl_hours` 会被夹到 `[1, LEAF_TTL_DAYS*24]`；缺省时取 `LEAF_TTL_DAYS` 天。
CSR 中请求的 CA 标志会被**强制忽略**（`is_ca = false`），CSR 只能拿到叶子证书。

## 存储（Store）

`Store` trait 有内存与 PostgreSQL 两套实现，处理器只依赖 trait（与 keystone 同构的接缝）。
Postgres 实现仅用**可移植标准 SQL**（`TEXT/BIGINT/BOOLEAN`、`PRIMARY KEY/NOT NULL/DEFAULT`、
参数化查询、`INSERT .. ON CONFLICT`），运行期查询（无编译期宏，构建**不需要数据库**），
因此后续可不改一行地跑在 FusionDB（pgwire）之上。

```text
ca_certificates(
  serial TEXT PRIMARY KEY, common_name TEXT, sans TEXT, profile TEXT,
  not_before BIGINT, not_after BIGINT,
  revoked BOOLEAN NOT NULL DEFAULT FALSE, revoked_at BIGINT, reason TEXT,
  pem TEXT NOT NULL
)
```

> 私钥**从不入库**：只有叶子证书 PEM 与元数据被持久化。

### Postgres 模式测试

默认 `cargo test` 走内存存储、无需数据库。Postgres 集成测试仅在设置了 `TEST_DATABASE_URL`
时运行：

```bash
docker run --rm -d --name kw-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=keyward \
  -p 127.0.0.1:55434:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55434/keyward \
  cargo test --test pg_store -- --nocapture
docker rm -f kw-testpg
```

## Docker

```bash
docker build -t holdfast/keyward:dev .
docker run --rm -p 127.0.0.1:8200:8200 -v keyward_ca:/ca holdfast/keyward:dev
curl -s http://127.0.0.1:8200/healthz   # ok
```

镜像为多阶段、非 root（uid 10001）、`VOLUME /ca`，自带 `keyward healthcheck` 探针（无需 curl）。

## 后续：keystone ↔ sluice 内网 mTLS 接入（仅说明，本步**不接线**）

Keyward 已经具备给内网双向 TLS 签发证书的全部能力。将来打通 keystone ↔ sluice 的 mTLS 时，
按如下方式消费 Keyward（这是**下一步**，不在本次范围内）：

1. **信任根**：两端都把 `GET /ca/root.crt`（即 Root CA）作为 CA 信任锚。CRL 通过
   `GET /ca/crl.pem` 拉取，配合 `openssl ... -crl_check` / rustls CRL 校验。
2. **keystone 服务端证书**：keystone 本地生成密钥与 CSR（CN/SAN = `keystone`，内网服务名），
   调 `POST /ca/sign-csr`（`profile: "server"` 或 `peer`）拿到证书；**私钥不出 keystone**。
3. **sluice 客户端证书**：sluice 同样本地生成密钥与 CSR（`profile: "client"` 或 `peer`），
   调 `POST /ca/sign-csr` 拿到证书，用于以客户端身份连到 keystone。
4. **校验**：keystone 用 `root.crt` 校验 sluice 的客户端证书，sluice 用 `root.crt` 校验 keystone
   的服务端证书；任一端被吊销则其序列号出现在 CRL 中。
5. 优先用 `/ca/sign-csr`（各服务自留私钥）；`/ca/issue` 仅作便捷场景（密钥经网络下发）。

> 注意：这条 mTLS 链路完全位于内网 `holdfast` 网络，与 Sluice 面向公网的 autocert TLS（`id.w33d.xyz`，
> Let's Encrypt）是**两套独立的信任体系**，互不影响。
