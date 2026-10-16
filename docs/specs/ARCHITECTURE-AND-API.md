# 架构与 API 约定

## 推荐拓扑

```text
管理员浏览器
   │ HTTPS + 密码认证 + RBAC
   ▼
管理控制面（Web/API、任务队列、后台 DB、探测调度）
   ├── DNS Provider Adapter ──► 经用户授权的权威 DNS API
   ├── SMTP Submission ───────► 邮件节点 587（STARTTLS）
   └── mTLS/签名任务 ─────────► 邮件节点 Agent（固定白名单方法）
                                      ├─ Postfix
                                      ├─ Dovecot
                                      ├─ OpenDKIM
                                      ├─ Roundcube/MySQL
                                      └─ 邮件数据与备份
```

Astrogate 当前网站机为 `154.94.226.49`，邮件机为 `23.94.184.57`。建议管理控制面先独立部署并通过独立子域名（例如 `admin.astrogate.sbs`）提供 HTTPS；正式上线前确认域名解析、反向代理、访问白名单和资源隔离。不要未经检查就将控制面直接部署到生产邮件机并覆盖其 Web 服务。

## 模块边界

- **Control API**：身份、权限、配置、任务、状态和审计；不持有 root shell。
- **DNS adapters**：官方 SDK/HTTPS API，凭据最小权限、加密储存；手工模式始终可用。
- **Mail node agent**：实例绑定、mTLS、固定 RPC schema、参数 allowlist、幂等操作；从不执行客户端传来的任意命令。
- **Mail transport**：SMTP submission STARTTLS，用于管理员单封邮件和诊断；不向网页端暴露 SMTP 密钥。
- **Monitor worker**：只读探针，任务超时并记录状态时间与来源。
- **Backup worker**：加密归档、校验、保留期、隔离恢复。
- **Audit**：记录 actor、action、target、request id、时间、结果、前后非秘密摘要；禁止记录密码、正文、token。

## 主要数据实体

`AdminUser`, `Role`, `Permission`, `Session`, `MfaCredential`, `MailDomain`, `MailNode`, `Mailbox`, `MailboxAlias`, `DnsProviderConfig`, `DnsRecordSnapshot`, `MailSendJob`, `MonitorCheck`, `Alert`, `BackupJob`, `RestoreDrill`, `AuditEvent`, `WebsiteUserConnector`。

秘密仅以 envelope encryption 或 OS secret store 储存；DB 中保存密文、版本、key id 和 metadata。绝不提供解密明文读取 API。邮箱密码使用邮件节点支持的安全密码哈希，后台只发起重置，不回读哈希。

## API 基线

所有管理 API 在 `/api/v1` 下，仅 HTTPS；JSON 错误结构稳定，分页有上限。敏感写操作支持 `Idempotency-Key`，可异步返回 `202` 和任务 id。每个请求有 trace/request id。

| Method | Path | 描述 |
| --- | --- | --- |
| `GET` | `/setup/status` | 只读检查是否需首次设置 |
| `POST` | `/setup/initialize` | 一次性初始化 Owner；只允许在未初始化时调用 |
| `POST` | `/auth/login` | 登录并返回安全 Cookie；支持 CSRF/token 配合 |
| `GET` | `/overview` | 服务/域名/备份状态摘要 |
| `GET/POST` | `/domains` | 列出/新增管理域 |
| `GET` | `/domains/{id}/dns/desired` | 期望 DNS 记录清单 |
| `POST` | `/domains/{id}/dns/check` | 检测实际记录和传播 |
| `POST` | `/domains/{id}/dns/plan` | 生成 dry-run diff，不写 DNS |
| `POST` | `/dns/plans/{id}/apply` | 经授权二次确认后执行变更 |
| `POST` | `/dns/plans/{id}/rollback` | 有快照前提下回滚 |
| `GET/POST` | `/mailboxes` | 列出/创建邮箱（按权限） |
| `POST` | `/mailboxes/{id}/password-reset` | 通过安全通道设置新密码，不返回当前密码 |
| `POST` | `/mailboxes/{id}/disable` | 暂停邮箱 |
| `POST` | `/mailboxes/{id}/enable` | 恢复邮箱 |
| `GET/POST/DELETE` | `/aliases` | 管理别名；所有权/循环校验 |
| `POST` | `/mail/test-send` | 给授权测试地址发送单封测试邮件 |
| `GET` | `/mail/queue` | 队列摘要和状态，不含正文 |
| `POST` | `/mail/queue/{id}/retry` | 受限重试并审计 |
| `GET` | `/health/checks` | 最新探测结果 |
| `POST` | `/health/checks/run` | 启动受限诊断作业 |
| `GET/POST` | `/backups` | 查询/启动备份 |
| `POST` | `/backups/{id}/verify` | 完整性验证 |
| `POST` | `/backups/{id}/restore-drill` | 隔离恢复演练，不覆盖生产 |
| `GET` | `/audit/events` | 按角色读取过滤后审计日志 |

删除操作使用软删除或显式二次确认。权限校验在后端服务层执行，不能仅靠隐藏前端按钮。错误不得返回 secret、堆栈或敏感服务器路径。

## Agent RPC 约定

Agent 只接受已绑定控制面的短期签名作业，至少支持：`health.read`, `mailbox.list`, `mailbox.create`, `mailbox.disable`, `mailbox.enable`, `mailbox.password_reset`, `alias.create`, `alias.delete`, `service.status`, `service.reload_allowlisted`, `mail.queue.summary`, `mail.queue.retry_allowlisted`, `backup.create`, `backup.verify`, `dns.local_preflight`。

每个动作必须定义版本、参数类型/长度/字符集、允许域、运行时间上限、固定执行能力和失败返回码。拒绝 `command`、shell 字符串、任意路径、任意服务名、任意 SQL、任意 host/URL。网络请求要有 egress allowlist，避免 SSRF。所有作业都可以查询状态，输出经过 secret/地址脱敏。

