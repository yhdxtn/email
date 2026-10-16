# Astrogate Mail Admin 0.1.0 — 验证与部署报告

日期：2026-10-16。状态：**密码直登版本已部署；邮件生产验收未完成（`productionAccepted=false`）。**

## 当前线上状态

管理入口：[https://admin.astrogate.sbs/](https://admin.astrogate.sbs/)。本轮发布后首页返回 HTTP 200，`GET /api/v1/setup/status` 返回 `needsSetup=false`、`productionAccepted=false`、`version=0.1.0`。管理员账号已初始化。前端加载新资源 `/assets/index-CC_MoFfe.js`，资源中未发现 TOTP/OTP 登录提示；现在登录只需用户名和密码。

控制面位于 `23.94.184.57` 的 `/opt/astrogate-mail-admin-release-20261016-password-login`，由 HAProxy SNI → Nginx `127.0.0.1:9443` → loopback 前端 `127.0.0.1:8088` 提供。PostgreSQL 与后端未公开宿主机端口。Postfix、Dovecot、Nginx、HAProxy 发布后均为 active；PostgreSQL 健康，backend/frontend 容器 running。原源码目录保留在 `/opt/astrogate-mail-admin`，本轮没有删除或重建 `control-db` 数据卷。

发布前创建并验证 PostgreSQL custom-format 备份 `/root/astrogate-pre-password-login-20261016.dump`（权限 `0600`），保留旧镜像标签 `rollback-password-login-20261016`。新源码包未包含 `.env` 或 `secrets/`；部署时从原目录复制配置及秘密文件到受限权限的发布目录。源码归档 SHA-256：`b5653477c4ccc92c64e66bf90fc098db320df8a48e057331fa286ea61e18bd8b`。

## 本轮验证

- Maven `verify`：`BUILD SUCCESS`；7 项 `ControlPlaneIntegrationTest` 与 5 项 `ClientIpResolverTest` 通过。集成测试直接覆盖“密码登录后建立会话”以及高危操作错误密码拒绝、正确密码重新认证 5 分钟。
- 前端 Vitest：17 项通过；Vue 类型检查与生产构建通过。线上 Docker 重建再次通过前端类型检查和 Vite production build，npm audit 报告 0 vulnerabilities。
- Docker Compose 配置校验和 backend/frontend 镜像构建成功。服务更新后前端首页、setup 状态接口和控制面容器均通过线上检查。
- 登录资源扫描未发现 TOTP/OTP 登录提示。尚未使用管理员真实凭据执行线上登录，因此线上凭据验证仍由用户刷新页面后完成；密码登录行为本身已由集成测试覆盖。

## 登录与安全边界

在 [管理后台](https://admin.astrogate.sbs/) 刷新页面，使用之前提供的管理员用户名和密码登录，不会再出现 TOTP 绑定步骤。管理登录目前是密码单因素；会话最长 8 小时。高风险写操作仍需要 5 分钟内再次输入管理员密码并确认。请仅使用 HTTPS，并在服务器部署层配置可信来源 IP 限制。

`productionAccepted=false` 是预期状态，表示产品尚未完成生产验收。Agent 邮件节点及账户写入、真实 SMTP/TLS 收发、DNS provider 自动写入、QQ/Gmail 回信验收、完整灾备、安全与依赖审计均未完成；当前上线只确认控制面和直接登录入口可用，不代表邮件管理功能已可用于生产写入。

管理站点证书由手动 DNS-01 签发，有效期至 **2027-01-14**；尚未配置 NameSilo API 自动续期。建议于 **2026-12-15** 开始续期，并按 `docs/OPERATIONS.md` 验证证书、DNS、管理页及邮件站点。

## 回滚材料

旧源码目录、镜像标签和数据库备份均保留。源码/镜像回退不代表数据库 schema 回退；执行数据库恢复前必须在克隆环境验证，禁止删除 `control-db` 卷或运行 `docker compose down -v`。本轮没有改变邮件服务配置。

## 其他未完成事项

网站用户连接器、DNS/SMTP provider 实测、完整灾备与恢复、管理员离线密码恢复、邮件发送与退信监测、证书自动续期和全量生产安全验收仍待实现或验证。逐项范围见 `docs/ACCEPTANCE.md`、`docs/THREAT-MODEL.md` 与 `docs/OPERATIONS.md`。

## 2026-10-16 侧边栏更新

管理员侧边菜单已按“工作台、邮箱管理、投递与节点、监控与恢复、账户与系统”分组，支持折叠/展开、当前页面高亮及按管理员角色过滤；菜单在窄屏下保留滚动导航。管理员登录页和控制台侧边栏提供独立的普通邮箱用户入口。邮箱用户仍在 `https://mail.astrogate.sbs/` 使用完整邮箱地址和邮箱密码；邮箱账号不等同于后台管理员。

前端 Vitest 共 **20 项**通过，Vue 类型检查与生产构建通过；服务器 Docker 前端镜像构建成功，仅重建并重启了 `frontend`，`backend` 和 `postgres` 未重启。线上管理页与邮箱页均返回 HTTP 200，管理 setup 状态仍为 `needsSetup=false`、`productionAccepted=false`；浏览器确认五个分组、子菜单和邮箱登录入口已加载。此次只改动控制台导航与说明，没有改邮箱服务、DNS、证书、数据库卷或管理员凭据。`productionAccepted=false` 保持不变。
