# Grantmint Rust 授权服务

自托管的中文 Web 授权后台：一套后台管理多个应用，每份授权绑定一台设备；首次联网激活后可以离线使用到合同到期。管理员续约后重签，客户主动联网同步新证书。后台是普通浏览器页面，不需要 Tauri。

## 组成

- `server/`：Rust / Axum / PostgreSQL 服务，管理员会话、应用、授权、激活、续期与审计。
- `dashboard/`：中文 React Web 页面。
- `crates/license-protocol/`：Ed25519 v2 协议和共享签名向量。
- `verifiers/rust/`：无网络的离线 SDK 与演示 CLI。

生产部署不运行 Java、策略引擎、浮动席位、心跳、支付 Webhook 或 v1 新签发。仓库保留 Java 模块及已有协议 fixture 供迁移核对；它们不进入当前 Docker 镜像和发布链。不要用旧 `docker-compose.yml` 启动 Rust 服务。

## 启动

1. 将 `deploy.env.example` 复制为 `.env.deploy`，填写数据库密码、至少 12 字符的管理员密码、访问地址；将 `config/keys.example.json` 复制为 `config/keys.json`。
2. 构建镜像：

   ```sh
   docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml build
   ```

3. 为每个应用生成独立密钥，命令只输出公钥注册信息，私钥保存在命名卷中：

   ```sh
   docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml run --rm --no-deps key-tools keygen app-2026 app-2026.seed
   ```

   将输出对象加入 `config/keys.json` 数组。文件已存在时命令拒绝覆盖；不要把生产 seed 提交到仓库。
4. 启动并等待健康检查：

   ```sh
   docker compose -p grantmint-rust --env-file .env.deploy -f compose.deploy.yml up -d --wait
   ```

5. 打开 [本机管理页面](http://127.0.0.1:8180)，登录后选择已部署公钥创建应用，再创建授权。数据库迁移由独立一次性容器先完成，失败时服务不会启动。

生产 HTTPS、备份、密钥轮换和独立迁移说明见 [Docker 部署](docs/deployment/docker.md)。

## 授权规则

- 每份授权固定一台设备，必须有明确未来停用时刻，无宽限期。
- 页面日期按北京时间当天 00:00 停用；提前七天的提醒由客户端 SDK 状态计算。
- 创建只展示一次激活秘密，设备完成私钥挑战后才得到可运行证书。
- 续期保持应用、授权和设备身份，递增合同修订；设备保存新证书并确认后，后台才显示已确认。
- 服务端停止不影响未到期离线授权。后台撤销不能立即禁用已下载的离线证书。

SDK 不等于完整的生产客户端接入。GlueSight 的硬件指纹采集、DPAPI/系统保护存储、提醒展示和工件门禁在其自身仓库实现；本仓库的 CLI 为互操作演示，不能当作防管理员修改的安全存储。

## 开发与验证

```sh
cargo test --manifest-path crates/license-protocol/Cargo.toml --locked
cargo test --manifest-path verifiers/rust/Cargo.toml --locked
cargo test --manifest-path server/Cargo.toml --locked
```

服务端集成测试要求设置 `TEST_DATABASE_URL`，使用专门的 PostgreSQL 测试数据库；缺少配置时会失败，不静默跳过。测试创建隔离 schema，不清空用户数据库。前端在 `dashboard/` 运行 `npm ci`、`npm test`、`npm run lint`、`npm run build`。开发代理的后端 `PUBLIC_ORIGIN` 应与浏览器地址完全一致。

- [文档索引](docs/README.md)
- [Rust 精简架构](docs/architecture/offline-device-licensing.md)
- [服务 API](docs/api/rust-service.md)
- [离线 SDK 与 CLI](verifiers/rust/README.md)

服务端沿用 AGPL-3.0，独立协议与 Rust 客户端库为 Apache-2.0；各模块保留相应许可证声明。
