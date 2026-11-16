# Rust v2 离线校验器

Apache-2.0 客户端库，不依赖服务端 AGPL 模块。支持 `offline_device` v2 证书、设备挑战签名及激活时间回执；v1 证书不能作为设备绑定授权使用。库和 CLI 均不访问网络，激活 HTTP 交互由调用方通过 TLS 完成。

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
```

## 安全调用契约

- `TrustedKeys` 的签名 key ID 和公钥必须来自应用内置配置或可信更新，不能从证书/激活响应提供的公钥建立信任。
- `ExpectedDevice.product_id` 来自应用配置，`license_id` 来自当前设备已登记的授权身份；不能从待验 token 回填后声称完成产品/授权隔离。
- `fingerprint_hash` 必须由当前设备的硬件 provider 重新采集并按 `fingerprint_version=1` 规范生成。不能读取 token 内的摘要作为本机值；本库不负责 Windows/Linux 标识采集。
- `DeviceIdentity` 需要本机私钥 seed，校验时检查其公钥摘要，并对随机本地挑战执行签名/验证以证明持有私钥。复制公钥和证书不足以通过校验；复制整机状态或修改客户端仍超出纯软件保证。
- `accept_activation` 仅用于首次在线激活：调用方必须保存本次主动向真实服务发出的待完成挑战，并把对应 `ActivationChallenge` 传入。该函数核验挑战原文、nonce、产品、设备、证书 serial 和签名的服务时间，不允许把任意旧响应作为新的时间锚点。
- 首次激活成功后，持久保存 `VerificationState`。正常离线运行调用 `verify` 必须加载该状态；丢失/损坏不能当首次启动重置，必须进入联网恢复流程。当前服务器是否支持恢复以 API 文档为准，库不会自行放行。
- 状态及设备 seed 必须通过 Windows DPAPI/受限 ACL、Linux 系统密钥存储或其他保护存储实现防篡改和原子替换。**本 crate 不实现这些 OS 适配，也不实现 GlueSight 工件调度入口。** CLI 仅用于开发/互操作验证，不能直接作为生产安全存储。
- 每次校验使用墙钟 UTC 秒；进程内传入“自此次加载/上次成功更新 state 后”的单调时钟流逝秒数，再将返回 state 原子持久化并重置单调时钟锚点。高频校验时必须保留单调时钟的亚秒余量，累计满一秒后再推进秒级锚点，不能每次取整为零后丢弃余量。不要每次都用零，或把总进程运行时间重复累加。跨休眠应重新核对墙钟；无可信硬件时无法彻底阻止整机快照回滚。

`verify` 成功表示证书签名、身份和时间状态检查完成，**不一定允许启动业务**。必须使用 `result.status.allows_new_work()`：只有 VALID/EXPIRING 返回 true，EXPIRED 返回 false。到期后仍返回经过认证的证书信息，便于 UI 展示及续期入口。业务层在每次接收新工件前校验，已开始工件是否允许完成由业务调度器控制。

EXPIRING 在到期前 7 × 86400 秒开始，`now >= exp` 为 EXPIRED。5 分钟墙钟回拨容差不增加有效期，生效时间取墙钟和可信下界较大者。超过容差返回 ClockSuspect；revision 或 binding_version 低于受保护高水位返回 Rollback。

解析器限制 128 KiB 输入，采用 serde_json 默认递归深度限制，拒绝重复 JSON key、浮点/指数表示、非规范 base64url、缺失必填字段、未知版本/算法和无界期限。证书序号与时间必须处于跨 Java/Rust/TypeScript 安全整数范围。

## CLI 互操作流程

以下命令在本机测试目录运行，示例路径均为占位文件。设备 seed 文件为原始 32 字节，命令不会将其打印到终端。`keygen-demo` 在 Unix 创建 0600 文件；Windows 应在受限临时目录使用，**没有 DPAPI 加密**。不要使用生产设备密钥进行该演示。

```sh
grantmint-offline keygen-demo device.seed
```

输出仅包括 `devicePublicKey`（标准 Base64 的原始 32 字节公钥）和 `deviceKeyHash`。调用方向 `/v2/licenses/challenges` 提交产品/授权、激活秘密、公钥以及当前设备指纹，保存响应为 `challenge.json`，随后：

```sh
grantmint-offline sign-challenge device.seed challenge.json PRODUCT_UUID LICENSE_UUID FINGERPRINT_HASH
```

该命令检查服务挑战是否精确绑定当前产品、授权、公钥和指纹，再输出 `challengeId` 与 `signature`（base64url）。调用方使用随机幂等键向 `/v2/licenses/activate` 提交签名，保存响应 `activation.json`。在程序中固定可信公钥；CLI 演示的 `trusted-keys.json` 格式为：

```json
{"product-signing-key-id":"BASE64_RAW_32_BYTE_PUBLIC_KEY"}
```

```sh
grantmint-offline accept-activation device.seed activation.json challenge.json trusted-keys.json PRODUCT_UUID LICENSE_UUID FINGERPRINT_HASH state.json
```

`state.json` 必须不存在，命令拒绝覆盖已有高水位。激活须在挑战有效窗口完成，且本机时间正确；异常时间不通过重放旧激活绕过。调用方把响应中 `token` 原文保存为 `license.token`，之后可以断开网络运行：

```sh
grantmint-offline verify device.seed license.token trusted-keys.json PRODUCT_UUID LICENSE_UUID FINGERPRINT_HASH state.json
```

CLI 输出状态、证书 serial 和到期秒数，不输出 token、seed 或激活秘密。有效/即将到期退出码 0；到期退出码 3；输入、验签、绑定或时间状态错误退出码 1。CLI 每次是独立进程，因此传入单调流逝值 0；长时间运行的应用必须使用库接口结合单调时钟。

CLI 的 JSON state 未加密/认证，只提供创建权限及文件替换示例。应用不能把它当成防管理员修改的安全存储。并发进程共享同一 state 时，调用方必须加锁协调“读取→校验→更新”；演示 CLI 不提供多进程事务锁。

## 验证范围

测试覆盖产品/授权/设备/指纹隔离、原始字节签名与篡改、精确提醒/到期、版本和时间回退、严格解析及时间回执重放。`tests/java_fixture.rs` 直接引用 Java core 的唯一共享 fixture；Java测试断言其签发输出完全相同，Rust验证该证书及回执并在离线十天后继续使用，到期当刻停止。

测试中的公开 seed 仅用于固定跨语言向量，不能用于部署。这里的校验测试不代表已经实现 Windows/Linux 安全存储、机器指纹采集、可信时间恢复 API、客户端自动弹窗或业务工件门禁。
