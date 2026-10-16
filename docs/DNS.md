# DNS 配置、预览与回滚

## 来源与期望状态

域名注册商不等于 DNS 托管商。先看实际 NS，再选择手工或 Cloudflare。不要因为历史交接写着 NameSilo 就默认调用 NameSilo DNS API。本版未实现 NameSilo/DNSOwl API 适配。

生成的主要记录分开显示：mail 主机 A、域 MX、SPF TXT、`selector._domainkey` DKIM 公钥 TXT、`_dmarc` TXT。网站根域 A 与 www A 不属于邮件向导管理范围。支持的是 IPv4 mail A；IPv6 与 autoconfig/autodiscover 服务配置尚未实现。

DKIM 输入必须是该邮件机实际签名对应的公钥。后台不会生成或读回 DKIM 私钥，不应拿示例公钥去匹配其他机器的私钥。SPF 中不存在的 relay、重复 SPF 与未实际启用的 DMARC 强策略都可能破坏投递，提交前人工核对。代码只提供结构校验和记录比较，不是完整邮件 DNS 语义审计器。

## 手工方式

在域名页面填写期望记录，复制逐条模板，到实际 DNS 服务商控制台修改邮件相关记录。模板里的 TTL 是期望值；公共递归查询的当前结果不能证明全球传播完成。DKIM 未填时会明确缺少公钥，不伪造一条绿色通过记录。

PTR/rDNS 通常由 IP/VPS 服务商设置，不是本平台可写的普通 Zone 记录。本版提供当前 PTR 检查和操作提示，但未完成所有正反向一致性语义校验；供应商提交和验证需人工处理。

## Cloudflare 方式

部署人员先验证当前权威 NS 确实为对应 Zone 的 Cloudflare nameserver，创建仅目标 Zone 所需 DNS 读取/编辑权限的 token，并在 UI 显式选 Cloudflare 与正确 Zone ID。token 服务端加密保存，不从读取 API 回显，不允许自定义任意 API base URL。

实现采用官方 DNS records list 与 batch 接口，批量限制和结果错误均按失败处理。计划记录 managed slots 的快照、目标、差异及配置指纹，有效期十五分钟。Owner/DnsAdmin 重新认证后输入页面确认语句执行。外部记录/配置发生变化会拒绝旧计划。网络超时或不可确定响应标为 unknown；不要把 unknown 当失败直接覆盖重试。

回滚先比较当前外部状态与该次应用的结果，只有没有后续漂移才按已保存快照恢复管理范围内的记录。它不是全 Zone 回滚，也不删网站 A、无关 TXT 或别人的新修改。持久状态与 provider 返回之间仍存在分布式不确定窗口；应检查 API 实际结果。

## NameSilo / DNSOwl 状态

NameSilo 的官方通用 API 文档说明：API 使用 HTTPS GET，版本参数为 `version=1`，可请求 XML 或 JSON，API key 放在查询参数中。查询参数可能进入代理访问日志、错误追踪或诊断输出，因此适配器必须对完整 URL 做密钥脱敏并关闭重定向。参考：[NameSilo API Reference](https://www.namesilo.com/api-reference)。

当前官方页面未能核实 DNS 记录操作的精确方法名、字段、响应结构和错误码，所以本版不提供 NameSilo/DNSOwl 自动写入。不要从记忆或旧示例推断接口后直接操作生产 Zone。后续需要单独实现 provider：逐条处理非事务性变更，操作前保存快照，遇到超时重新读取状态并标记 `unknown`，只允许修改平台管理的记录槽位。真实联调应使用专用测试 Zone，不能用 `astrogate.sbs` 生产区做 canary。

## 尚待验收

Cloudflare HTTP 合约/错误注入测试、专用测试 Zone 应用与回滚、TTL/公共递归与权威查询差异、分段 TXT/IDNA/复杂现有 SPF/DMARC、DNS SEC 等未做完整验证。不得把编写了 provider adapter 等同于真实账号联调完成。

实现参考：Cloudflare 官方 DNS records API `https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/`；Dovecot 官方 passwd-file 文档 `https://doc.dovecot.org/2.3/configuration_manual/authentication/passwd_file/`。这些用于核对接口/适配格式，并不替代用户输入规格。
