# 部署、DNS、备份与灾难恢复要求

## 当前 Astrogate 基线

- 网站主机：`154.94.226.49`；当前网站记录继续指向该主机。
- 邮件主机：`23.94.184.57`。
- 邮件域：`astrogate.sbs`；SMTP/IMAP host：`mail.astrogate.sbs`。
- 组件：Postfix、Dovecot、OpenDKIM、Roundcube、PHP-FPM、MySQL。
- 客户端/网站提交：587 STARTTLS；IMAP SSL/TLS：993；服务器间 SMTP：25。
- 网站 SMTP 用户为完整邮箱名；秘密只能独立注入服务端密钥管理。
- 目前邮箱账户通过 `mail-account` 在服务器命令行维护。管理后台不存在。
- NameSilo 是注册商；当前 NS 显示 DNSOwl 权威 DNS。NameSilo 注册 API 不等于 DNS 区域 API。
- 现有测试：QQ 收到邮件；Gmail 收到但进垃圾箱；外部回信和原始邮件头尚未确认。
- 新邮件 IP 当前 PTR 仍为供应商主机名；应由 IP 提供商改为 `mail.astrogate.sbs`。
- 当前证书验证/续期路径依赖网站机转发；新控制面不能未经演练破坏现有路径。

## 期望 DNS（切换前重新查询）

| 类型 | 名称 | 当前期望值 |
| --- | --- | --- |
| A | `mail.astrogate.sbs` | `23.94.184.57` |
| MX | `astrogate.sbs` | priority `10` → `mail.astrogate.sbs.` |
| TXT | `astrogate.sbs` SPF | `v=spf1 ip4:23.94.184.57 ~all`；其他合法发信源合并为一条 SPF |
| TXT | `mail202610._domainkey.astrogate.sbs` | 使用私有管理资料中的公开 DKIM 公钥；私钥绝不可发布 |
| TXT | `_dmarc.astrogate.sbs` | `v=DMARC1; p=none; rua=mailto:dmarc@astrogate.sbs` |
| A | 网站主机（如 `www`） | 继续指向 `154.94.226.49`，由网站负责人单独维护 |
| PTR | `23.94.184.57` | 由 IP/VPS 服务商设置为 `mail.astrogate.sbs`，并检查正反向匹配 |

后台必须先查询权威 NS 和当前记录；只有用户授权并配置了实际 DNS 托管商 API Token，且 provider 支持对应操作时才自动写入。否则生成可复制清单、传播检查和状态。变更前展示 diff，确认后写入；保留变更前快照和回滚步骤。不要重复创建第二条 SPF。不要把网站 A 记录和邮件 MX 混成一个配置。

### DNS 插件策略

建立可扩展 provider adapter：`discoverAuthority`, `listRecords`, `planChanges`, `applyChanges`, `rollbackChanges`, `checkPropagation`。先实现手工模式；自动化只针对官方 API 和文档明确的 provider，做适配器测试和权限说明。当前 authoritative provider 需由 NS 发现和用户确认；NameSilo 可仅作为 Registrar 记录，不得误判为 DNS provider。API 失败不能回退到未授权的网页自动化。

PTR/rDNS 通常不在权威 DNS zone 中，必须显示 IP 服务商操作步骤和当前值；不可显示为已经自动修复。

## 控制面和 Agent 部署

建议控制面部署到单独管理主机/隔离容器，使用独立 HTTPS 主机名（候选 `admin.astrogate.sbs`）。生产启用前检查该 DNS 名称是否可用、证书链、VPN/IP allowlist 和代理配置；不要擅自改现有网站/邮件域名记录。控制面数据库应单独部署和备份。

邮件节点 Agent 通过受控安装包/systemd 部署于邮件主机，绑定控制面证书，默认不开放公网管理端口；优先 mTLS 出站长连接或仅从固定控制面 IP 接入。Agent 升级和密钥轮换需审计。控制面/Agent 不得共享 root SSH 密钥。

生产导入顺序：

1. 只读检查操作系统、Postfix/Dovecot/OpenDKIM/Roundcube 版本、服务状态、域名、用户/别名、路径和现有备份。
2. 显示兼容矩阵、将接管的功能和预期变更；无法识别的配置标记为“不支持/需要人工处理”。
3. 先在克隆或测试机验证只读导入、邮箱账号适配、发信、DNS、备份。
4. 生产启用写权限前要求独立管理员确认、已有加密备份和回滚方案。
5. 变更按单个可逆任务执行，展示结果；不得一次性重装或覆盖整机配置。

## 端口和协议

| 端口 | 用途 | 暴露建议 |
| --- | --- | --- |
| 25/TCP | SMTP 服务器间投递 | 公网邮件节点必需；需提供商允许出站/入站 |
| 587/TCP | SMTP submission | 公网开放但强制 STARTTLS 与认证 |
| 993/TCP | IMAP TLS | 仅用户确需远程 IMAP 时开放 |
| 80/TCP | ACME HTTP-01 挑战/跳转 | 只保留证书所需路径 |
| 443/TCP | Roundcube 或管理 Web | HTTPS；密码单因素管理后台需额外 IP/VPN 来源限制 |
| Agent 管理 | 节点控制 RPC | 默认不开放公网；固定来源 mTLS 或出站连接 |

## 备份要求

完整备份范围至少包括：

- 邮件 Maildir/附件/文件属主和 UID/GID。
- 邮箱域、账户安全哈希、别名、配额、转发设置及管理后台数据库。
- Postfix、Dovecot、OpenDKIM、Roundcube、Nginx/PHP 对应配置及数据库。
- DKIM 私钥、Roundcube `des_key`、数据库 secret、Agent 身份密钥、TLS 证书/续期账户元数据恢复清单。
- 管理员审计和域名/DNS provider 配置（API token 加密储存，不能明文打进普通导出）。

采用客户端加密、异地副本、权限隔离和保留轮换；每日/每周策略可配置。监控备份新鲜度、加密、大小、校验和失败。每月至少做一次隔离恢复演练；定期将加密备份复制到离线或独立账户存储。仅备份数据库无法恢复邮件，单一服务器本地备份也不能抵御整机/账户故障。

## 从空机部署与恢复步骤

1. 准备受支持 Debian/Ubuntu 版本、安全更新、固定 IP、磁盘、时间同步和受限 SSH；确认出站 TCP 25 是否可用。
2. DNS 先用低 TTL 规划，核对当前 MX、SPF、DKIM、DMARC 与网站记录。新 IP 由 IP 服务商设置 PTR。
3. 安装并加固控制面、数据库、Agent；首次 Owner setup 后关闭初始化端点，启用 HTTPS、强密码和来源限制。
4. 安装/恢复邮件组件和 Maildir，恢复身份/别名/权限/数据库/配置；若不恢复 DKIM 私钥，先发布新 selector 后切换签名。
5. 获取 `mail.astrogate.sbs` TLS 证书并运行续期 dry-run，确认 HTTP-01 或 DNS-01 路径能持续工作。
6. 恢复管理后台设置和 DNS provider（密钥应单独重新配置或通过专用加密恢复流程），检查 Agent mTLS。
7. 执行 DNS diff，不立即切换；预检 A/MX/SPF/DKIM/DMARC/PTR、端口、证书和反向解析。
8. 在隔离环境验证邮件登录、SMTP、IMAP、附件、本域互发、队列、DKIM、匿名 relay 拒绝、备份和恢复。
9. 经授权切换 DNS；对本人控制的 QQ/Gmail 做外部收发与回信检查，并检查原始头。保留旧机/备份用于回滚。
10. 网站机与邮件机独立恢复；网站 A 只在网站迁移时修改。当前证书同步/转发若依赖网站机，需单独恢复或替换并演练。

## 回滚约束

DNS 回滚前先将新机新增邮件/用户数据备份并合并；绝不以旧备份覆盖新邮件。Agent 的配置写操作需留前一版本快照；恢复演练默认只能写隔离目录/测试实例。外部 DNS 回滚应展示将修改的记录并再次确认。

