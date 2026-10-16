$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw '请先安装并启动 Docker Desktop。脚本不会自行安装系统组件。' }
if (-not (Test-Path '.env')) { python scripts/init_secrets.py --dev; if ($LASTEXITCODE -ne 0) { throw '初始化失败' } }
$settings = Get-Content '.env'
if (($settings -notcontains 'LOCAL_DEV=true') -or ($settings -notcontains 'APP_ORIGIN=http://127.0.0.1:8088')) { throw '现有配置不是本地开发配置；拒绝自动修改。' }
docker compose up --build -d
if ($LASTEXITCODE -ne 0) { throw '构建或启动失败，请查看完整错误；不要视为已完成。' }
Write-Host '请在本机访问 http://127.0.0.1:8088；初始化令牌位于 secrets/setup-token。'
