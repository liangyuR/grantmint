# Grantmint v2 公共协议

Apache-2.0 独立 crate，无服务端、数据库或 HTTP 依赖。提供挑战原文、Serde DTO、设备公钥摘要和 canonical Ed25519 签名；只接收调用方 SigningKey，不保存生产私钥。

activation_message 保持原 Java v2 字节；operation_message 为 Sync/Ack 添加独立域和目标 serial。格式化函数要求调用方先验证规范 UUID、32 字节 nonce、公钥/指纹编码及 fingerprint_version=1，不负责授权认证。

canonical_json 递归排序键，限制深度64、JSON 90KB，拒绝非安全整数。验签必须针对原编码段，不重新序列化。HTTP 层仍须限制大小并拒绝重复 JSON key，Value 签名函数不能恢复被解析器覆盖的信息。

cargo test --locked 对共享 Java fixture 逐字节比较 GMT 和 GMT-TIME，避免换语言改变既有协议。公开 fixture seed 禁止用于生产。
