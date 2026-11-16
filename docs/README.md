# 设计文档

- [多应用管理控制台](features/multi-application-console.md)：当前产品上下文、管理流程与能力范围。
- [单设备激活与长期离线授权](features/offline-device-activation.md)：v2 创建、设备激活和 Rust 离线校验的使用规则及边界。
- [Docker 部署](deployment/docker.md)：同源静态管理页面、服务端、数据库和 HTTPS 部署。
- [Rust 精简授权服务方案](architecture/offline-device-licensing.md)：后续采用 Rust 单体替换 Java 后端，明确功能取舍、迁移、续期和部署。

当前运行后端仍为 Java，已实现范围以使用文档为准。Rust 后端、续期和应用业务接入尚待实现，换机审批不纳入首期。
