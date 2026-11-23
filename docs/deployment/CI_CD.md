# CI 与发布

当前交付物是 Rust 授权服务、公共协议、离线 SDK 和中文 Web 页面。CI 不再构建 Maven/GraalVM 或旧 v1 SDK；保留的 Java 源码用于存量迁移及公共协议向量，不属于生产镜像。

PR 检查包括：

- Windows/Linux Rust 协议与离线 SDK 的 fmt、测试和 Clippy。
- Linux Rust 服务端检查，连接真实 PostgreSQL 16，在独立测试 schema 验证认证、并发绑定、续期事务、同步/确认和回滚。
- 中文 Web 的 lint、业务测试和生产构建。
- Docker 构建、一次性迁移、健康检查、Web 访问，以及旧 v1 路由关闭验证。

Rust 工具链为 1.91.1，依赖由各 crate Cargo.lock 固定。SQL 迁移固定 LF，避免跨平台摘要差异。测试数据库配置缺失会明确失败，不把未执行集成测试报告为通过。

`v*` 标签触发发布，构建 Linux amd64/arm64 二进制及迁移工具，生成校验和，并发布服务端/前端两个 GHCR 镜像。发布不需要生产授权签名私钥，也不会包含管理员凭据。镜像部署前按 docs/deployment/docker.md 备份数据并运行迁移。

本项目的 release workflow 不代替业务验收，发布标签须对应已通过 CI 的预期提交；版本号、标签及实际源码修订应在发布前核对。本次实现不自动创建发布标签。
