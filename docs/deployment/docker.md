# Docker 部署

普通中文 Web 页面由 Caddy 提供，Rust 服务连接 PostgreSQL。三个常驻服务为 gateway、license-server、postgres；migrate 是发布时的一次性数据库迁移任务，不是额外业务服务。容器内不运行 Java 或 Vite。

## 本机启动

复制 `deploy.env.example` 为 `.env.deploy`，复制 `config/keys.example.json` 为 `config/keys.json`。填写不同的数据库和管理员强密码，管理员首次初始化要求至少 12 字符。默认地址为 `http://127.0.0.1:8180`，若改端口须同时改 `GRANTMINT_PUBLIC_ORIGIN`；Origin 必须与浏览器实际使用地址相同。

```sh
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml config --quiet
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml build
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml run --rm --no-deps key-tools keygen app-2026 app-2026.seed
```

keygen 输出 `{keyId,publicKey,privateKeyFile}`，将它加入 `config/keys.json` 数组后启动：

```sh
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml up -d --wait
```

可先用空数组启动检查登录，再配置密钥并重启 license-server；没有可用密钥时不能创建应用或签发授权。密钥注册文件不含私钥，但仍作为本地部署配置管理。不要使用例子中的公开测试 seed。

`.env.deploy` 和真实密钥配置不提交。显式 `-f` 不加载旧的 `docker-compose.override.yml`。固定项目名管理本环境，新的 `rust-database`、`rust-signing-keys` 卷不会复用 Java 的 `database`/`signing-keys` 卷。

首次启动后，修改环境中的管理员密码不会重置已有账号。不要通过删除数据库来更改管理员密码；账号恢复需独立受控运维，不属于首次 bootstrap。

## HTTPS 与网络

填写 `GRANTMINT_DOMAIN` 为 DNS 主机名；填写 `GRANTMINT_ADMIN_CIDRS` 为管理网段或 VPN CIDR，默认仅私网。生产启动：

```sh
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml -f compose.deploy.tls.yml up -d --build --wait
```

TLS 覆盖会开启 Secure 会话 Cookie，并把 PUBLIC_ORIGIN 设置为该 HTTPS 域名。后续运维 `up` 仍需两个 `-f`，避免改回 HTTP。本机模式仅绑定 127.0.0.1，生产仅网关发布 80/443，数据库不映射宿主端口。`/healthz` 只在容器内部访问，网关不公开；旧 v1、issuance、webhooks 和 actuator 路径返回 404。

如果网关前还有代理，应同时核对管理网段限制与后端可信代理设置。Rust 默认不信任转发头，`TRUSTED_PROXY_IPS` 只接受明确代理 IP，不直接信任客户端提供的 X-Forwarded-For。未配置时经过同一网关的设备请求共享该网关地址的限流额度，不能把任意公网地址加入信任列表来解除限制。

## 密钥

每应用独立 Ed25519 seed，原始 32 字节，Unix 文件权限 0600。key-tools 以服务 UID 10001 写入专用卷，create-new 防止覆盖；正常服务只读挂载私钥。启动核对文件路径、权限及公钥匹配，缺失/错误直接失败，不自动换钥。管理页仅选择部署人员已注册的公钥，绝不上传私钥。

添加密钥后更新 JSON 注册数组并重启 license-server。切换某应用签发 key 前，先让客户端可信公钥集合包含新 key；然后管理页选择新签发 key。保留旧公钥至其证书到期，未升级客户端不应收到它无法识别的签名。

## 健康检查与更新

```sh
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml ps
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml logs --tail 100 license-server gateway
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml exec license-server curl -fsS http://127.0.0.1:8080/healthz
```

更新镜像后必须重新执行迁移任务，再启动服务；启动时会检查迁移版本，不自动修改数据库。可用 `run --rm migrate` 显式复验。迁移检测到 Flyway 表时拒绝运行，避免把 Rust 结构写入旧数据库。Docker 构建和依赖版本以锁文件为准。

```sh
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml build
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml run --rm migrate
docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml up -d --wait
```

## 备份与迁移

备份 PostgreSQL、密钥卷及公钥注册映射，限制备份权限。恢复后验证最新 revision、serial 与证书摘要，不能只检查服务是否启动。不要对有业务数据的环境执行 `down -v`。

从 Java v2 迁移使用 [数据迁移说明](../operations/rust-migration.md)。工具默认只检查，只允许写入独立空业务库；旧服务冻结写入后才能应用。v1、暂停、提前强制过期或仍有保留期内挑战的批次会拒绝导入。迁移不自动转换或删除私钥，旧 hex seed 与新 raw seed 格式不同，必须由部署人员安全转换并核对公钥。

旧客户端已有证书仍可离线运行；切换后若产生新修订，不能直接恢复旧数据库回滚，须冻结写入并迁回增量，否则保持停止签发。
