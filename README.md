# Astrogate Mail Admin · 0.1.0

**管理入口已上线 HTTPS；管理员账号已初始化。生产验收仍未完成。**

包含真实 API、数据库迁移、中文 Vue 页面、邮件节点 Agent、任务执行器和安全测试。2026-10-16 已在 `23.94.184.57` 实际构建并启动 Compose 控制面。当前 `admin.astrogate.sbs` 的 A 记录指向该服务器，管理入口 HTTPS 返回 HTTP 200；HAProxy 按 TLS SNI 分流至 Nginx `127.0.0.1:9443`，管理站点再反向代理到仅监听 loopback 的控制面 `127.0.0.1:8088`。邮件入口仍是 `mail.astrogate.sbs`。管理员账号已初始化，接口报告 `needsSetup=false`、`productionAccepted=false`。本轮密码直登改动已完成集成验证并部署到线上；Agent 邮件节点接入、SMTP、DNS API 与真实邮箱写入仍未验收。详细证据和边界见 `validation/REPORT.md`、`docs/ACCEPTANCE.md`。

管理站点证书由手动 DNS-01 签发，有效期截至 **2027-01-14**；尚未配置 NameSilo API 自动续期。请在到期前约 30 天（**2026-12-15**）安排续期，并按 `docs/OPERATIONS.md` 完成检查。没有将 DNS API 凭据或其他秘密写入文档。

## 先看这里

后台控制面与现有邮件服务使用独立容器和数据库卷；不自动安装、重装或覆盖现有 Postfix/Dovecot/Roundcube。新建节点默认只读，未配置 Agent/SMTP/DNS API 时会显示未配置，不伪造成功。生产初始化令牌和密钥只在服务器现场生成，不放入源码包。管理员使用用户名和密码直接登录；高风险写操作要求近期重新输入管理员密码。密码单因素登录降低账户保护强度，应启用来源 IP 限制。

技术栈：Java 21 / Spring Boot 3 / Spring Security / Flyway / PostgreSQL 17；Vue 3 / TypeScript / Vite；独立 Python Agent + systemd。PostgreSQL 是唯一管理数据库；Agent 的 SQLite 仅作为本机幂等与重放防护账本，不是第二套控制面数据库。

## 本地启动入口

需要事先安装 Docker Engine + Compose（Windows 可用 Docker Desktop）、Python 3，并允许下载声明的镜像及依赖。下列是新环境的启动方式；本次已在 Ubuntu 22.04 邮件机验证实际构建、启动和初始化状态接口。线上管理域名与 HTTPS 已配置，但初始化和生产验收仍未完成。

Windows PowerShell，在解压后的项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1
```

Linux/macOS，在项目根目录执行：

```bash
bash scripts/dev.sh
```

启动入口只创建新的本地控制面配置、数据库卷和容器，不连接生产邮件节点。配置文件已存在但不是明确的本地开发配置时会拒绝覆盖。构建成功后，在浏览器打开 `http://127.0.0.1:8088`。首次初始化令牌由 `secrets/setup-token` 提供，创建 Owner 后即可使用用户名和密码登录；初始化入口随后关闭。高风险操作会要求近期重新输入管理员密码。该 HTTP 模式只适合本机验证，不能公开到公网。线上管理入口的 HAProxy/Nginx 拓扑是单独配置的，不能直接套用 `deploy/nginx-mail-admin.conf.example`；详情见 `docs/INSTALL.md`。

查看首次初始化令牌（只在自己的可信终端查看，不发给其他人）：

```powershell
Get-Content .\secrets\setup-token
```

Linux 对应 `cat secrets/setup-token`。初始化密码至少 14 个字符。管理后台采用用户名和密码直接登录；高风险写操作会要求在最近 5 分钟内再次输入管理员密码。密码单因素登录降低了账户保护强度，因此应始终通过 HTTPS 访问，并在部署层配置 `ADMIN_SOURCE_IPS` 限制来源。

## 工程目录

```text
backend/     Java API、鉴权、DNS/SMTP 业务、数据库任务队列、Flyway SQL
frontend/    中文管理界面、表单、差异预览与高危操作确认
agent/       白名单 RPC、mTLS/签名、只读扫描、兼容账户适配、文件备份
scripts/     本地启动、随机密钥、离线证书、分层测试与源码扫描
deploy/       Compose 配套配置、Caddy/Nginx 示例、systemd 与 Agent 模板
docs/        安装/使用/DNS/运维/威胁模型/接口/验收差距/原始规格
validation/  实际测试输出、JUnit XML 和本次验证报告
```

## 已写入源码的主要功能

| 模块 | 本版实现范围 |
|---|---|
| 管理员 | 一次性初始化、用户名/密码直接登录、角色权限、CSRF、会话吊销、高危密码重新认证 |
| 邮箱及域 | 域记录、账户创建/停用/恢复/改密/配额/延迟删除；兼容节点经任务执行确认 |
| DNS | 手工记录模板与检测；Cloudflare 适配代码；差异预览、状态变化拒绝覆盖、快照回滚 |
| 节点与任务 | 只读接入、固定 RPC、实例绑定、幂等、超时/中断结果未知，不自动重复外部副作用 |
| 受限发信 | 明确测试收件人名单、发件人限制、预览确认、配额、有限附件、SMTP 接受状态 |
| 监控与审计 | Agent/服务/部分端口 TLS 检查、站内告警、任务与追加式审计 |
| 本地文件备份 | 加密、完整性验证、只写隔离目录的文件提取演练，不等于完整灾备 |

页面连接真实 API。真实数据不可用时显示空状态/未采集/离线；网站用户连接器明确标为未实现，没有填充虚构用户。

## 测试

本地开发机需先安装 Java 21、Maven、Node 22、Docker、Python 测试依赖及前端依赖。依赖准备见 `docs/DEPENDENCIES.md`。运行全套提供的测试与隔离容器 smoke：

```bash
python3 scripts/test_all.py
```

缺少工具、构建失败或测试失败会返回非零，绝不静默跳过并报“全部通过”。`python3 scripts/test_all.py --local` 只运行能够独立执行的子集，不能替代 Spring/数据库/Vue/Docker 验证。测试不会连接真实邮件服务器。每次运行的日志和结果清单保存在独立的 `validation/runs/<runId>/` 目录，主清单为 `results.json`。`validation/` 根目录中既有的 `.txt`、`.xml`、`.json` 是旧轮次快照，不应与新运行结果拼作同一轮证据。

## 文档导航

安装：`docs/INSTALL.md`；管理操作：`docs/ADMIN.md`；DNS：`docs/DNS.md`；备份与运维：`docs/OPERATIONS.md`；安全边界：`docs/THREAT-MODEL.md`；验收差距：`docs/ACCEPTANCE.md`；接口：`docs/API.md`；依赖与锁定：`docs/DEPENDENCIES.md`；实现决策：`docs/DECISIONS.md`。

本版不得跳过这些发布门槛：全量构建和迁移测试、真实邮件机克隆验收、DNS provider 合约测试、真实 SMTP/TLS 收发验收、完整灾备演练、安全与依赖审计。生产环境不能使用实验室模式、共享密钥、公开 HTTP、未知路径适配或未校验的恢复操作。

源码采用 MIT License。原始用户规格保留在 `docs/specs/` 供追溯。所有测试地址为虚构/保留用途，真实密钥只在目标机器或临时测试目录生成。
