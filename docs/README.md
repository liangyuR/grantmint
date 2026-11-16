# 设计文档

- [多应用管理控制台](features/multi-application-console.md)：当前产品上下文、管理流程与能力范围。
- [单设备激活与长期离线授权](features/offline-device-activation.md)：v2 创建、设备激活和 Rust 离线校验的使用规则及边界。
- [Docker 部署](deployment/docker.md)：同源静态管理页面、服务端、数据库和 HTTPS 部署。
- [多应用单设备离线授权改造方案](architecture/offline-device-licensing.md)：本 fork 的待实现设计，覆盖管理端、激活协议、Rust 客户端、续期和部署。

已交付范围以使用文档为准；完整方案中的续期、换机审批和应用业务接入仍需后续实现。
