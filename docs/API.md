# API 使用与契约状态

统一前缀 `/api/v1`。生产采用 `__Host-AGSESSION` 安全Cookie，本地开发用 `AGSESSION`；不使用放在localStorage里的长期Bearer。先GET `/auth/csrf` 取得token/headerName，再对POST/PUT/DELETE带对应header，并在浏览器保持same-origin credentials。不同role在控制器和service执行最小权限检查。

登录通过 `/auth/login` 校验用户名和密码后直接建立最长 8 小时的会话。高风险写操作需先向 `/auth/reauth` 提交 `{ "password": "..." }`，再按页面提供的准确 confirmation 提交。异步写操作需 `Idempotency-Key`，16–100位字母/数字/下划线/短横线；重试同一动作必须保留原键。创建计划不等于执行。错误返回code/message/requestId，不返回密码、原始SMTP凭据或完整内部栈。

一般任务返回id/status，查看 `/tasks/{id}`。`unknown` 代表副作用不确定而非必定失败，不要自动重发。列表大多限制最近100条；审计支持before参数，页面导出仅当前页。

后端配置了Springdoc运行时端点 `/api/v1/openapi`，需登录。本环境没有运行Spring，因此没有取得或验证实际运行时OpenAPI。随附 `openapi.route-inventory.json` 是直接从控制器注解生成的OpenAPI形状的路由清单，不含完整请求/响应schema；不得将它当成完整契约验收通过。完整契约应在可构建环境导出并与下列清单、DTO、错误分支逐项比对。

## 实际声明路由

| 方法 | 路径 | 来源 |
|---|---|---|
| GET | `/api/v1/admins` | AdminController |
| POST | `/api/v1/admins` | AdminController |
| PUT | `/api/v1/admins/{id}` | AdminController |
| GET | `/api/v1/setup/status` | AuthController |
| POST | `/api/v1/setup/initialize` | AuthController |
| GET | `/api/v1/auth/csrf` | AuthController |
| POST | `/api/v1/auth/login` | AuthController |
| GET | `/api/v1/auth/me` | AuthController |
| POST | `/api/v1/auth/reauth` | AuthController |
| POST | `/api/v1/auth/logout` | AuthController |
| GET | `/api/v1/auth/sessions` | AuthController |
| DELETE | `/api/v1/auth/sessions/{id}` | AuthController |
| GET | `/api/v1/overview` | ControlController |
| GET | `/api/v1/nodes` | ControlController |
| POST | `/api/v1/nodes` | ControlController |
| POST | `/api/v1/nodes/{id}/scan` | ControlController |
| POST | `/api/v1/nodes/{id}/enable-management-plan` | ControlController |
| GET | `/api/v1/tasks` | ControlController |
| GET | `/api/v1/tasks/{id}` | ControlController |
| POST | `/api/v1/plans/{id}/confirm` | ControlController |
| GET | `/api/v1/settings` | ControlController |
| PUT | `/api/v1/settings` | ControlController |
| GET | `/api/v1/health/checks` | ControlController |
| POST | `/api/v1/health/checks/run` | ControlController |
| GET | `/api/v1/audit/events` | ControlController |
| GET | `/api/v1/website-users` | ControlController |
| GET | `/api/v1/alerts` | ControlController |
| POST | `/api/v1/alerts/{id}/silence` | ControlController |
| GET | `/api/v1/domains` | DnsController |
| POST | `/api/v1/domains` | DnsController |
| PUT | `/api/v1/domains/{id}` | DnsController |
| PUT | `/api/v1/domains/{id}/dns/provider` | DnsController |
| GET | `/api/v1/domains/{id}/dns/desired` | DnsController |
| POST | `/api/v1/domains/{id}/dns/check` | DnsController |
| POST | `/api/v1/domains/{id}/dns/plan` | DnsController |
| GET | `/api/v1/dns/plans` | DnsController |
| GET | `/api/v1/dns/plans/{id}` | DnsController |
| POST | `/api/v1/dns/plans/{id}/apply` | DnsController |
| POST | `/api/v1/dns/plans/{id}/rollback` | DnsController |
| GET | `/livez` | LivenessController |
| GET | `/api/v1/mailboxes` | MailboxController |
| POST | `/api/v1/mailboxes` | MailboxController |
| POST | `/api/v1/mailboxes/{id}/{action}` | MailboxController |
| POST | `/api/v1/mailboxes/{id}/delete-plan` | MailboxController |
| GET | `/api/v1/aliases` | MailboxController |
| POST | `/api/v1/aliases` | MailboxController |
| DELETE | `/api/v1/aliases/{id}` | MailboxController |
| POST | `/api/v1/mail/test-send` | OperationsController |
| GET | `/api/v1/mail/sends` | OperationsController |
| POST | `/api/v1/mail/sends/{id}/observation` | OperationsController |
| GET | `/api/v1/mail/queue` | OperationsController |
| POST | `/api/v1/mail/queue/{queueId}/retry` | OperationsController |
| POST | `/api/v1/mail/queue/{queueId}/delete-plan` | OperationsController |
| GET | `/api/v1/backups` | OperationsController |
| POST | `/api/v1/backups` | OperationsController |
| POST | `/api/v1/backups/{id}/verify` | OperationsController |
| POST | `/api/v1/backups/{id}/restore-drill` | OperationsController |
| GET | `/api/v1/restore-drills` | OperationsController |
| POST | `/api/v1/nodes/{id}/import-mailboxes` | OperationsController |
