# 原始验收用例逐项对照

## 线上状态快照（2026-10-16）

已确认 `admin.astrogate.sbs` A 记录指向 `23.94.184.57`，管理 HTTPS 返回 HTTP 200；HAProxy 按 SNI 分流到 Nginx `127.0.0.1:9443`，之后代理至控制面 `127.0.0.1:8088`。现有邮件入口仍是 `mail.astrogate.sbs`。管理证书以手动 DNS-01 签发，2027-01-14 到期，未配置 NameSilo API 自动续期。

以上只确认 DNS/HTTPS 入口可达，不代表产品验收或邮件管理功能可用。管理员账号已初始化，`/api/v1/setup/status` 返回 `needsSetup=false`、`productionAccepted=false`。密码直登版本已部署，登录页不再要求 TOTP；Agent 接入、DNS/SMTP 和真实邮箱写入仍需分别验收。`deploy/nginx-mail-admin.conf.example` 不是现网配置：它假设 Nginx 监听公网 80/443，不能直接用于 HAProxy→Nginx `127.0.0.1:9443` 的链路。证据及验证范围见 `validation/REPORT.md`。

状态定义：“已测子集”仅指报告中的具体独立测试；“代码已写”不表示应用构建或生产链路成功；“未实现”保留为发布阻断。

| 原验收项 | 已写入代码/已测范围 | 未完成或未验证 |
|---|---|---|
| 1.空环境启动/一次性初始管理员 | Docker Compose 控制面和 PostgreSQL 新库实际启动；setup 状态 API 返回 HTTP 200；集成测试覆盖一次性 setup；管理员可直接用密码登录；密码登录集成测试及线上构建通过 | 邮件生产验收仍未完成，线上 `productionAccepted=false` |
| 2.未登录/RBAC/密码登录 | 会话/CSRF/RBAC、密码限速、密码直登与近期密码重认证通过 Maven 集成测试；线上首页 HTTP 200，发布资源不含 TOTP/OTP 登录提示 | 密码单因素安全评估、密码丢失恢复流程与完整生产安全验收未完成 |
| 3.Agent账户操作/幂等/回滚 | Python临时目录账户profile、签名重放/mTLS、异常回滚已测 | 后台到真实Postfix/Dovecot2.3认证收信全链路；未知现有profile适配 |
| 4.DNS手动+自动dry-run/回滚 | Java核心期望状态/网站记录保护断言；Cloudflare计划/快照实现 | provider HTTP合约及真实测试Zone联调；完整传播/正反向检查 |
| 5.受限单封邮件与Message-ID | 预览确认、限额/附件/SMTP状态源码 | 真实SMTP/TLS错误矩阵、收件箱人工验收、完整退信解析 |
| 6.诊断区分各种故障 | Agent诊断源码，传输边界实测；站内告警代码 | 综合故障注入；IMAP合成登录未实现；部分遥测未采集 |
| 7.加密备份/隔离恢复 | 本地声明文件认证加密、篡改拒绝、隔离提取测试 | S3/轮换/全量DBdump/完整Maildir与DKIM/TLS/服务恢复未实现 |
| 8.扫描无秘密/负向安全 | 多项Agent负向测试；有限模式源码扫描 | 全制品扫描、依赖CVE、SAST与渗透测试、特权helper实机验收 |
| 9.OpenAPI/Compose空卷smoke | Compose 镜像实际构建；新 PostgreSQL 卷启动；setup API、未认证拒绝和 CSRF 拒绝 smoke 已运行 | runtime OpenAPI 与真实接口完整比对未做；smoke 未覆盖初始化后管理流程及生产邮件节点 |

额外未实现：网站用户连接器、冻结/解冻与重置集成；邮件/Webhook告警；自动TLS续期/Agent证书轮换；多节点部署配置管理；全量安装/升级/回滚编排；管理员密码丢失恢复流程；自动permanent邮箱清理；autoconfig/autodiscover；解析后的完整SBOM/依赖锁。

**因此原提示词的全部验收要求尚未满足，不能将本版标为完整可交付生产系统。** 管理域名 HTTPS 可达只是入口层状态，不改变这一结论。本次交付的是有真实源码、部分已执行测试与明确未完成项的开发版本。
