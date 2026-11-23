# Rust 授权服务 API

全部 JSON 字段 camelCase；错误 `{error: "stable_code"}`。UUID 为字符串，时间 RFC3339 UTC；过期边界为 `now >= expiresAt`。请求最大 128KiB。应用/授权不硬删除。

## 运行

`grantmint-server migrate` 显式创建新数据库结构；检测 Flyway 表存在即拒绝。`grantmint-server serve` 校验迁移并运行，监听 `BIND_ADDR`（默认 `0.0.0.0:8080`），`GET /healthz` 检查 PostgreSQL。不会自动运行迁移。

数据库：`DATABASE_URL` 或 `DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD`。首次管理员 `ADMIN_USERNAME/ADMIN_PASSWORD`（空用户表时要求密码至少12字符）；后续不自动重置密码。`COOKIE_SECURE=true` 默认，开发 HTTP 可设 false；`PUBLIC_ORIGIN` 设置管理页面精确 Origin，默认 `http://localhost:8080`。`TRUSTED_PROXY_IPS` 可逗号分隔精确信任的代理IP，默认不信任转发头。

`KEYS_DIR=/keys`；`SIGNING_KEYS_FILE=/config/signing-keys.json`：

```json
[{"keyId":"app-2026","publicKey":"标准Base64原始32字节公钥","privateKeyFile":"app.seed"}]
```

私钥文件为原始32字节，Unix需无group/other读写执行权限且当前进程只读加载；公钥必须匹配。文件名不决定keyId或应用身份。keyId配置全局唯一，数据库只可归属一个应用；密钥切换选新的已配置keyId，旧公钥保留。禁止符号链接和逃逸KEYS_DIR。没有密钥的应用不签发；服务器不生成替代私钥。

## 会话

POST `/admin/auth/login` `{username,password}` → `{username,csrfToken}`，设置 HttpOnly / SameSite=Strict / Secure 的 `grantmint_session` cookie，有效8小时。
GET `/admin/auth/me` → 同对象。全部管理写操作（login除外）带 `X-XSRF-TOKEN: csrfToken`，会话失效返回401，CSRF失败403。POST `/admin/auth/logout` →204并使会话失效。带Origin的管理请求须匹配PUBLIC_ORIGIN。

## 应用

- GET `/admin/v2/signing-keys` → `[{keyId,publicKey,applicationId:null|UUID}]`；仅部署配置的key。
- GET `/admin/v2/applications` → 应用数组（包括归档）；POST同路径 `{id?:UUID,slug,name,description?:"",signingKeyId}` →201应用。
- PUT `/admin/v2/applications/{id}` `{name,description,signingKeyId}` →应用；slug/UUID不可修改。
- POST `/admin/v2/applications/{id}/archive` →应用；归档阻止新建授权及续期，不剥夺已有合同激活/同步。
- GET `/admin/v2/applications/{id}/keys` → `[{keyId,publicKey,active}]`。

应用对象 `{id,slug,name,description,signingKeyId,archivedAt:null|timestamp,createdAt}`。

## 授权

GET `/admin/v2/licenses?applicationId=&page=0&size=50` → `{content:[detail],totalElements,totalPages,number,size}`（size上限100）。
POST同路径 `{applicationId,customer:{name,email},expiresAt,entitlements:{}}` →201 `{...detail,licenseId:id,activationSecret}`，秘密仅本次展示。
GET `/admin/v2/licenses/{id}` → detail。
POST `/admin/v2/licenses/{id}/revoke` `{reason}` → detail。
POST `/admin/v2/licenses/{id}/renewals` `{expectedRevision,newExpiresAt,idempotencyKey,reason}` → detail；重复相同请求返回原响应，不同请求409。同设备绑定不会改变；不允许权益变更。新期限必须晚于旧期限和现在，已过期未撤销可续期。

detail：`{id,keyId,applicationId,applicationName,customer,expiresAt,entitlements,status,revision,bindingVersion,createdAt,revokedAt,signedToken,devicePublicKey,fingerprintHash,fingerprintVersion,serial,deliveryStatus,renewals}`。status=`created|active|expired|revoked`；未绑定bindingVersion=0，设备/token/serial为null；deliveryStatus=`not_activated|pending|confirmed`。
renewal：`{id,oldExpiresAt,newExpiresAt,revision,serial,confirmedAt,reason,createdAt}`。

## 设备协议

保留旧激活路径/字段：POST `/v2/licenses/challenges` `{productId,licenseId,activationSecret,devicePublicKey,fingerprintHash,fingerprintVersion:1}` → `{challengeId,nonce,message,expiresAt}`。message是UTF8挑战原文的base64url无填充编码。POST `/v2/licenses/activate` `{productId,licenseId,challengeId,signature,idempotencyKey}` → `{licenseId,keyId,token,revision,bindingVersion,serverTime,timeReceipt}`。激活秘密仍为64字符hex，与旧Java SHA256摘要兼容。

POST `/v2/licenses/sync-challenges` `{productId,licenseId,devicePublicKey,fingerprintHash,fingerprintVersion:1,operation:"sync"|"ack",serial?:UUID}` → `{challengeId,nonce,message,expiresAt,serial}`。sync可省serial，绑定当前证书；ack必须指定当前serial。
POST `/v2/licenses/sync` 同activate请求；POST `/v2/licenses/acknowledgements` 同请求加`serial` → `{serial,confirmedAt}`。

activate域为原`grantmint.activate.v2`；sync/ack域分别`grantmint.sync.v2`/`grantmint.ack.v2`，与activate相同七个后续字段，最后追加一行serial，无尾换行。若挑战后续期改变证书，返回409 `certificate_changed`要求新挑战。确认使用独立ack挑战，不能复用sync挑战。

nonce5分钟单次消费；同幂等key+同签名24小时内返回原响应，改请求409。每授权最多64条保留挑战，过期记录清理；HTTP每IP每分钟60设备请求、10登录请求。错应用/授权/秘密统一401 `invalid_activation_credentials`。撤销阻止后续激活/同步，不影响已离线设备的现有证书。

## 审计

GET `/admin/v2/audit?applicationId=&licenseId=&page=0&size=50` →分页对象，content每项 `{id,actor,applicationId,licenseId,action,detail,createdAt}`。不记录密码、秘密、私钥或完整证书。

## 测试准入

真实PG用例保护：未登录及CSRF缺失不能写；两设备并发绑定仅一个成功；响应丢失幂等恢复及改请求拒绝；私钥加载/签名失败无绑定/修订残留；并发续期只接受一个expectedRevision且重复请求不累加；同步/ack不能跨操作重放且新修订后旧挑战拒绝；撤销不能通过激活/同步/续期复活；共享fixture签发与客户端解释一致。
