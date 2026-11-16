# Docker 部署管理控制台

本入口部署中文多应用管理控制台、v1 兼容授权及 v2 单设备激活服务。[v2 使用说明](../features/offline-device-activation.md)介绍长期离线校验流程；续期重签、设备恢复和业务应用接入仍属于[后续方案](../architecture/offline-device-licensing.md)。

当前 Compose 运行 Java 服务。后续将按 Rust 精简方案替换后端，保持网关、授权单体和 PostgreSQL 的三服务结构；新镜像与迁移工具尚未交付，本页命令仍针对当前实现。

## 本机启动

需要 Docker Engine / Docker Desktop 与 Docker Compose 2.24.4 或更新版本（TLS 配置使用 `!override`）。首次构建会下载 Node、JDK、Caddy、PostgreSQL 及 npm/Maven 依赖。

1. 把根目录 `deploy.env.example` 复制为 `.env.deploy`，分别填写随机数据库密码和管理员密码，不要使用示例或复用密码。可以从密码管理器生成至少 32 字符随机值。`.env.deploy` 已被 Git 忽略；Linux 上设置权限 0600。
2. 在仓库根目录执行：

   ```sh
   docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml config --quiet
   docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml up -d --build --wait
   ```

3. 打开 `http://127.0.0.1:8180`，使用 `.env.deploy` 中的管理员账号登录。修改 `GRANTMINT_HTTP_PORT` 可避开端口冲突。

显式 `-f compose.deploy.yml` 不加载旧的 `docker-compose.override.yml`；固定 `-p` 让本部署的数据卷与本机演示环境隔离。后续所有命令使用相同项目名、env 文件和 compose 文件。数据库密码和管理员密码缺失时 Compose 会报错，不会使用弱口令回退。

管理员密码只在空数据库首次启动时创建账号。修改 env 文件不会重置已有管理员密码；使用现有密码修改 API/管理员恢复流程处理。数据库已有数据时也不能仅修改 env 中数据库密码，否则服务将无法连接。

## 对外 HTTPS

在服务器上为域名配置正确的 A/AAAA 记录、放行入站 80/443，并在 `.env.deploy` 填入：

```dotenv
GRANTMINT_DOMAIN=licenses.example.com
GRANTMINT_ADMIN_CIDRS=192.0.2.10/32 198.51.100.0/24
```

这里的地址是文档占位，必须换成管理员的真实出口 IP/VPN 网段；`private_ranges` 默认只允许私网来源调用管理 API。不要为了登录方便使用 `0.0.0.0/0`，公众客户端只需要 `/v1` 等许可接口。

```sh
docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml -f compose.deploy.tls.yml up -d --build --wait
```

Caddy 负责证书申请、自动续期、HTTP 跳转 HTTPS，以及静态页面和 API 的同源代理。TLS 模式显式启用 Secure session/XSRF cookie；本机 HTTP 模式显式关闭 Secure，只绑定回环地址。不得把本机 HTTP 端口改成公网监听后当作生产部署。

默认拓扑直接面向客户端，管理访问限制依据 TCP 对端 IP，不相信任意 `X-Forwarded-For`。如果再加负载均衡/CDN，先设计可信代理和真实来源地址校验，不能直接把代理的内网来源当作管理员授权。当前服务端未配置可信代理范围，许可接口按代理 IP 聚合限流；高并发生产部署应基于实际网络范围配置 `grantmint.validation.rate-limit.trusted-proxies`，不能通配信任所有代理。

## 网络与持久化

只有 gateway 发布端口。数据库位于独立内部网络，应用 8080 与 actuator 9090 不映射到宿主；actuator 保持容器回环监听。网关不转发 actuator、Prometheus 或 Swagger。管理 API 保留原路径和 cookie/CSRF 头，不去掉 `/admin` 前缀；前端深链接刷新回退到 index.html。

Compose 持久化 PostgreSQL、签名密钥、Caddy 证书与配置。普通 `down` 保留卷，**`down -v` 会永久删除这些数据**。升级前备份数据库与密钥/证书卷，验证恢复后已有授权仍可验签并可继续签发；不要仅备份数据库。

```sh
docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml ps
docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml logs --tail 100 grantmint-server gateway
docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml exec grantmint-server curl -fsS http://127.0.0.1:9090/actuator/health
```

TLS 部署运维命令同时带上 `-f compose.deploy.tls.yml`，尤其是后续 `up`，防止意外改回本机 HTTP 模式。

## 导入产品签名密钥

管理产品/策略不需要密钥；实际签发授权前，每个应用必须注册匹配的签名公私钥。页面只显示公钥和状态，私钥不通过浏览器输入或上传。

使用现有 CLI 的 `keygen --out` 在受控机器生成 Ed25519 seed 和公钥，或使用组织现有安全密钥生成流程。私钥格式支持 32 字节原始值、64 字符 hex 或 Base64；以下命令以 hex 文本 seed 为例。服务用户 UID 为 10001，文件必须为 0600。

Windows bind mount 常把文件映射成宽松权限，服务会拒绝读取，因此本部署使用 named volume。`key-import` 是手动运行的工具容器，默认不启动，无网络，只有它可写密钥卷，正常服务器只读挂载。

Linux shell 中：

```sh
cat /secure/product-2026.hex | docker compose -p grantmint-console --env-file .env.deploy -f compose.deploy.yml run --rm -T key-import -c 'set -eu; umask 077; set -C; cat > /keys/product-2026.hex; chown 10001 /keys/product-2026.hex; chmod 600 /keys/product-2026.hex'
```

PowerShell 7 中使用 `Get-Content -Raw` 读取同一个 hex 文件并管道到相同 Docker 命令。私钥通过标准输入传递，不放进命令参数或 env；`set -C` 拒绝覆盖已存在的文件。密钥轮换使用新文件名，不能覆盖仍用于旧证书的密钥。

然后使用已认证管理 API `POST /admin/products/{productId}/signing-keys` 注册 `keyId`、`privateKeyRef=file:/keys/product-2026.hex`、原始 32 字节公钥的标准 Base64 `publicKey` 和 `makeActive=true`。请求只包含私钥引用，不包含 seed；服务会验证公私钥匹配。保留密钥安全备份，不把 seed、数据库转储或 env 文件提交到 Git。

## 构建与验收

服务与管理页面均由多阶段 Dockerfile 构建。服务沿用 Java 21；控制台用 Node 22 构建后由 Caddy 提供静态文件，不运行 Vite 开发服务器。

如默认 Docker Hub 下载链路不可用，可在 env 中配置以下官方镜像副本，不需要改源码或关闭 TLS 校验：

```dotenv
JDK_IMAGE=public.ecr.aws/docker/library/eclipse-temurin:21-jdk
JRE_IMAGE=public.ecr.aws/docker/library/eclipse-temurin:21-jre
NODE_IMAGE=public.ecr.aws/docker/library/node:22-alpine
CADDY_IMAGE=public.ecr.aws/docker/library/caddy:2-alpine
POSTGRES_IMAGE=public.ecr.aws/docker/library/postgres:16-alpine
```

验收至少包括：三个服务 healthy、首页和深链接可访问、同源 cookie 登录、缺 CSRF 的写请求被拒绝、正确 CSRF 可创建应用、切换应用后策略/授权不串数据、actuator 外部请求返回 404、数据库和服务没有宿主发布端口。HTTPS 上线额外确认自动证书、Secure cookie 和管理来源网段限制；本机 HTTP 验证不能替代这些生产检查。
