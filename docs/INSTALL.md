# 安装与现有服务器接入

## 1. 部署前边界

本版没有经过任何 Linux 发行版的完整生产认证。目标候选为 Debian 12、Ubuntu 22.04/24.04；需在相同系统的克隆环境自行验收 Python/cryptography、systemd、Postfix/Dovecot 版本及权限。不要把“目标候选”理解成“已通过支持矩阵”。管理控制面应独立部署，不默认占用原邮件机的 80/443、邮件目录或数据库。

生产需准备独立管理域名、HTTPS 边缘反向代理、管理员访问 IP 策略、可用磁盘与备份目标、独立随机密钥、可信时间同步。Compose 本地 HTTP 只绑定 127.0.0.1:8088；后端和 PostgreSQL 没有宿主机公开端口。现有网站和邮件证书续期路由不由此项目覆盖。

### 当前邮件机的管理入口拓扑（2026-10-16）

`admin.astrogate.sbs` 的 A 记录指向 `23.94.184.57`，管理 HTTPS 已返回 HTTP 200；HAProxy 按 TLS SNI 分流至 Nginx `127.0.0.1:9443`，再代理到控制面 `127.0.0.1:8088`。邮件入口仍为 `mail.astrogate.sbs`。管理 TLS 证书通过手动 DNS-01 签发，有效期截至 **2027-01-14**，没有配置 NameSilo API 自动续期；应在到期前约 30 天（**2026-12-15**）启动人工续期和验证。管理员账号已初始化，`needsSetup=false`；`productionAccepted=false` 仍表示邮件节点、SMTP、DNS 与生产验收未完成。

`deploy/nginx-mail-admin.conf.example` 是通用示例，假设 Nginx 自己监听公网 80/443。它与当前 HAProxy→Nginx `127.0.0.1:9443` 的链路不同，**不可直接复制或启用到现有服务器**；复用前必须按实际 SNI、监听地址、证书路径和上游链路重新审核，并检查配置及回归现有邮件站点。

## 2. 新的管理控制面

先完成全量构建/测试，不要直接把尚未验证的版本部署为唯一管理工具。

```bash
python3 scripts/init_secrets.py --origin https://admin.example.test
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

将示例管理域名换成自己的域名。脚本拒绝覆盖现有 `.env`/`secrets`，也不会自动部署 Nginx、DNS 或邮件服务。`deploy/nginx-mail-admin.conf.example` 仅适合作为新环境的参考模板：若目标架构由 Nginx 直接监听公网 80/443，可在人工审核、替换证书路径与 allowlist、并通过 Nginx 配置检查后再启用。现有邮件机由 HAProxy 将管理 SNI 转给 Nginx `127.0.0.1:9443`，不能照搬该模板；见上方“当前邮件机的管理入口拓扑”。

数据库首次初始化脚本只针对本 Compose 新空卷：运行时账户 `astrogate_app` 与迁移账户 `astrogate_migrator` 分开。PostgreSQL 初始化所需凭据被复制到容器私有 tmpfs 并赋给 postgres 用户，避免把宿主机密钥放宽为全员可读。已有数据卷不会因修改 `.env` 自动重设数据库角色密码。密码轮换必须制定数据库与应用一致性步骤。

容器内存限制是安全边界，不是容量验证结果。构建机还需要额外内存和磁盘；应实测控制面与数据库的资源占用。不要据此认定原 2GB 邮件机足够运行整套系统。

## 3. 初始账号与 HTTPS

只在可信本机终端查看 `secrets/setup-token`，通过 HTTPS 向导创建唯一 Owner；随后使用用户名和密码直接登录。生产环境后台 Cookie 采用 Secure/HttpOnly/SameSite=Strict，CSRF 令牌通过独立接口取得。管理员会话最长 8 小时，高风险操作要求最近 5 分钟内重新输入管理员密码。当前采用密码单因素认证，务必通过 HTTPS 访问，并在部署层配置来源 IP 限制。`APP_ORIGIN` 必须与浏览器实际管理站点完全一致，包括非标准端口。

Nginx IP allowlist 由部署人员维护。应用默认不信任客户端提交的转发头。仅在所部署的应用版本明确支持可信代理解析时，才可配置 `ADMIN_TRUSTED_PROXY_CIDRS`：只列出实际代理到应用的那一跳的精确受控网段，并只使用由该代理覆盖写入的单值 `X-Real-IP`。HAProxy、Nginx/Caddy 的每一跳都要核对其覆盖/传递行为；不得设置 trust-all、`0.0.0.0/0` 或 `::/0`，也不得因登录不便而信任未经验证的 `X-Forwarded-For`。配置代理信任后仍应在边缘执行访问控制，并从可信和非可信来源测试。线上当前部署状态不能推断为已部署支持该配置的新应用代码。

## 4. 离线 Agent 证书

控制面与节点采用 mTLS，加上短期 HMAC 签名任务与实例绑定，不提供网页登录 root shell。

在可信管理机器生成证书（示例地址不可用于实际连接）：

```bash
python3 scripts/make_agent_pki.py --out /secure/agent-enrollment \
  --dns agent.example.test --ip 192.0.2.20 \
  --password-file secrets/agent-keystore-password
keytool -importcert -storetype PKCS12 -alias agent-ca \
  -file /secure/agent-enrollment/ca.pem \
  -keystore secrets/agent-client/trust.p12
```

keytool 提示时使用 `secrets/agent-keystore-password` 中同一密码，不把密码写进 shell 命令行。将 `client.p12` 放入 `secrets/agent-client/`，按后端运行 UID 设置目录/文件权限。把服务器证书/服务器私钥/CA 公钥、HMAC 签名密钥安全传给目标 Agent。**CA 私钥必须离线保存，不复制进后台或邮件机。** 客户端叶证书 SHA-256 填入 Agent 配置以便固定身份；服务器证书 SAN 必须匹配 AGENT_URL 主机名或 IP。证书为 90 天，续期及指纹轮换目前需人工协调，没有自动轮换工作流。

Java truststore 的实际装载和后台至 Agent 的跨语言 mTLS 尚需联调。已有的实际 mTLS 测试针对 Python Agent 传输边界，不等于该 Java 连接路径已通过。

## 5. 只读节点安装

先人工确认实际系统、邮件用户 UID/GID、路径和现有工具行为。交接包不包含原 `mail-account` 程序，因此不能推断它的参数，也不能直接调用或覆盖它。

安装到新的独立目录（需要管理员明确批准；本项目未自动执行这些步骤）：

```bash
python3 -m venv /opt/astrogate-mail-agent/venv
/opt/astrogate-mail-agent/venv/bin/pip install .
```

从 `deploy/agent.inventory.example.json` 建立 `/etc/astrogate-agent/config.json`。填写真实实例 ID、允许域、证书与签名密钥位置，保留 `adapter=inventory`、`write_enabled=false`、`allow_helper=false`。配置应 root 拥有且不可由普通用户改写，秘密文件 0600 并由 root 或 Agent 运行用户拥有且可读。不要把模板里的示例指纹当作可用指纹。

systemd 示例使用 `vmail` 用户；必须确认本机确有该用户且适合只读检查，再创建 `/var/lib/astrogate-agent` 等必要状态目录并授权。未经确认不要自动新建与实际邮件 UID/GID 不同的用户。安装 `deploy/astrogate-mail-agent.service` 后人工检查其沙盒权限并启用服务。

Agent 模板仅监听 loopback，不会自动暴露远端端口。管理控制面位于其他主机时，人工选择私有网卡/VPN 地址，更新 bind 和防火墙，只允许控制面访问 9089/TCP。mTLS 必须保持开启，不使用 `--lab`。

控制面 `.env` 的 `AGENT_URL=https://...:9089`、`AGENT_INSTANCE_ID` 必须与节点一致。当前仅支持一个 `primary` 部署连接，不是已完成的多节点连接管理器。在页面注册相同实例，运行只读扫描；检查实际状态，不应看到虚构健康项。

## 6. 写入接管门槛

本版唯一写入适配器是**严格声明的 Dovecot 2.3 passwd-file + Postfix text/hash maps 配置**。不支持任意现有目录、SQL/LDAP、Dovecot 2.4 或未知脚本结构。详见 `agent/node.py` 的兼容性判定与 `deploy/agent.managed-profile.example.json`。

先在克隆机建立经过审阅的配置/数据映射，验证 UID/GID、认证密码格式、收件映射、别名与所有写入回滚，再完成有效备份校验。Agent 本地配置需显式批准写入并满足最近备份与兼容检查；管理后台 Owner 另需重新认证、预览并确认启用管理。两端门槛缺一不可。

systemd 默认只能写 Agent 状态目录；通过人工审核的 drop-in 加入**具体** maps/Maildir/备份目录，不能放开整个 `/etc` 或 `/var`。本版不提供自动迁移生产配置的脚本，不要为绕过兼容检查修改程序返回“成功”。

## 7. 端口与外部服务

443/TCP 管理 HTTPS：仅管理员允许范围；8088/TCP：仅本机；数据库 5432：仅 Compose 内网；Agent 9089：仅私网允许的控制面。25/587/993 是已存在邮件服务的探测/通信目标，此 Compose 不启动或开放这些端口。

SMTP、Cloudflare API、DNS 权威查询和真实收发均需额外人工配置。邮件投递要求与 PTR、SPF、DKIM、DMARC、IP 声誉等外部条件有关；本平台不能保证 Gmail/QQ 收件箱到达。
