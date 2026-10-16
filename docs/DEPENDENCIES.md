# 依赖、版本和构建复现

前端依赖已解析并提交 `frontend/package-lock.json`；Dockerfile 使用 `npm ci`，缺锁文件会停止构建。2026-10-16 执行 `npm audit --audit-level=high` 返回 0 vulnerabilities；Vue 固定为 3.5.44。该结果来自 npm 当日公告数据库，不替代完整的源代码、镜像或供应链审计。

在联网开发/验收机器安装并验证：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r agent/requirements-test.txt
python -m pytest -q agent/tests tests
cd frontend
npm ci
npm test
npm run build
npm audit --audit-level=high
cd ..
mvn -B -f backend/pom.xml verify
```

2026-10-16 验证记录：Python 3.12 Linux 容器中 87 项通过；Java 21 / Testcontainers 中 5 项 Spring 集成测试通过；Maven `verify` 生成含 67 个组件的 CycloneDX SBOM；前端 13 项测试、类型检查、生产构建均通过。Docker Compose 镜像也已在 Ubuntu 22.04 邮件机实建并完成新空卷启动 smoke。详细边界见 `validation/REPORT.md`。

版本声明：cryptography 46.0.4；Java 21、Spring Boot 3.5.16；Vue 3.5.44、TypeScript 5.9.3、Vite 7.3.7、Vitest 4.1.11；PostgreSQL 17.11-bookworm。Docker 构建使用固定工具镜像标签；应在每次发布时重新扫描基础镜像和 SBOM，并按需升级安全补丁。

CycloneDX Maven 插件在 `verify` 阶段生成应用 SBOM。`docs/dependency-manifest.json` 仅是直接声明的依赖清单，不替代完整 SBOM。npm audit 与 SBOM 不能证明没有漏洞，发布仍须进行依赖、镜像、应用代码和目标运行环境的安全审查。

官方参考：

- Spring Boot 3.5.16：<https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now>
- Vite 支持分支及发行记录：<https://vite.dev/releases>、<https://github.com/vitejs/vite/releases>
- Vitest 安全公告：<https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9>、<https://github.com/vitest-dev/vitest/security/advisories/GHSA-5xrq-8626-4rwp>
- PostgreSQL 版本策略：<https://www.postgresql.org/support/versioning/>
