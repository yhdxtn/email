# 实现决策与规格差距

1. 交接 ZIP 只有规格，不含后端/前端/现有 mail-account 源码。因此按建议新建 Java21/Spring Boot3 + Vue3/TypeScript + PostgreSQL 控制面，没有混搭两套管理数据库。
2. 先不重装生产节点；对未知原路径与认证格式采用 inventory 只读适配，唯一可写 profile 限定为严格验证的 Postfix/Dovecot2.3 passwd-file。不能把未支持的真实系统伪装成已接入。
3. 低量异步操作用 PostgreSQL 任务队列，不增加 Redis。Agent 独立 Python服务， SQLite仅用于本机重放/幂等账本。控制面不提供SSH终端。
4. DNS 手工模式默认可用。第二适配器选择有官方API的 Cloudflare，但只有实际 NS匹配与显式token授权才可提交。不会因用户在NameSilo注册就自动写NameSilo DNS。
5. 无法安全实现/验证的外部用户目录、S3、完整灾备、邮件/Webhook告警以禁用或明确限制状态呈现，而非假按钮/假数据。
6. 不把SMTP接受等同收件箱到达，不把已排队等同节点成功，不把认证解密通过等同整个邮件系统恢复通过。
7. 当前只有一个primary Agent部署连接。模板、界面注册能力不等于完成多节点配置管理和多租户隔离。
8. 当前环境无Maven/Docker/PostgreSQL且不能下载npm/Maven依赖。已执行可独立运行的核心与Agent测试；声明和输出保留未通过/阻塞状态。没有伪造package-lock、完整SBOM、构建镜像或成品截图。
9. 交付目标调整为可继续构建和验收的工程源码，而不是声称实现了全部验收。差距是本次实际未完成内容，不代表原始规格已经被删减或变更。原规格仍保留供后续逐项完成。
