# Astrogate 邮件系统管理后台：AI 开发交接包

这是一份可交给代码生成 AI 或软件开发团队的项目规格包，目标是从源码实现一个可自托管、可部署、可监控、可备份恢复的邮件系统管理平台。它不是已完成的软件，也不会自动更改现有服务器或 DNS。

## 怎么使用

1. 将本目录提供给你使用的代码生成 AI，并把 `AI-IMPLEMENTATION-PROMPT.md` 全文作为主提示词。
2. 让 AI 在新的 Git 仓库中分阶段实现系统。要求它先阅读全部规格、输出实施计划，再直接创建可运行代码、迁移、测试、部署文件和操作文档。
3. 开发完成后先在隔离测试机验证，再评估导入当前邮件服务器。不要让 AI 直接重装或覆盖现有生产服务。

## 包内文件

- `AI-IMPLEMENTATION-PROMPT.md`：给代码 AI 的完整主提示词，可单独使用。
- `PRODUCT-REQUIREMENTS.md`：用户角色、后台页面、功能边界和版本范围。
- `ARCHITECTURE-AND-API.md`：推荐架构、安全调用边界和主要 API 合约。
- `DEPLOYMENT-DNS-BACKUP.md`：当前部署背景、域名/DNS 设置、部署、备份和重建要求。
- `SECURITY-AND-ACCEPTANCE.md`：安全要求、监控状态定义和验收标准。

## 当前实际环境（背景）

- 网站服务器：`154.94.226.49`
- 邮件服务器：`23.94.184.57`
- 邮件域名：`astrogate.sbs`；主机名：`mail.astrogate.sbs`
- 当前邮件组件：Postfix、Dovecot、OpenDKIM、Roundcube、PHP-FPM、MySQL
- 邮箱账号目前由服务器命令 `mail-account` 管理；`https://mail.astrogate.sbs` 是 Roundcube 邮箱客户端，不是管理后台。
- QQ 已收到测试邮件；Gmail 测试邮件进入垃圾邮件。PTR、真实外部回信和 Gmail 原始认证头仍需继续核实。
- NameSilo 是域名注册商；当前权威 DNS 由 DNSOwl NS 托管。注册商、权威 DNS 托管商、IP 服务商是不同职责。

**安全边界：**本包不包含密码、API Token、服务器私钥、SSH 私钥或邮件数据。当前服务器的真实凭据不得让代码 AI 写入仓库、示例配置、日志或测试夹具。DNS 自动修改能力取决于实际托管商 API 和用户授权；无可用 API 时必须提供手动记录向导。

