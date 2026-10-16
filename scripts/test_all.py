#!/usr/bin/env python3
"""Fail-closed test runner. --local is a clearly labelled SUBSET, never production acceptance."""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SOURCE_HASH_EXCLUDED_DIRS={'.git','.venv','node_modules','target','dist','build','coverage','.pytest_cache','.mypy_cache','.ruff_cache','.local','__pycache__','secrets'}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

def git_source_id() -> str:
    git=shutil.which('git')
    if git:
        try:
            result=subprocess.run([git,'-C',str(ROOT),'rev-parse','--verify','HEAD'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=3)
            if result.returncode==0 and result.stdout.strip():
                commit=result.stdout.strip()
                status=subprocess.run([git,'-C',str(ROOT),'status','--porcelain','--untracked-files=no'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=5)
                if status.returncode==0:return commit+('-dirty' if status.stdout.strip() else '')
        except (OSError,subprocess.TimeoutExpired):pass
    # The supplied source snapshot may contain incomplete Git metadata. Hash the source tree
    # instead of silently recording an unknown revision, while excluding credentials/caches.
    digest=hashlib.sha256()
    for current,dirs,files in os.walk(ROOT):
        relative_dir=Path(current).relative_to(ROOT)
        dirs[:]=sorted(name for name in dirs if name not in SOURCE_HASH_EXCLUDED_DIRS and not(relative_dir.as_posix()=='validation' and name=='runs'))
        for name in sorted(files):
            path=Path(current)/name;relative=path.relative_to(ROOT)
            if path.is_symlink() or relative.name=='.env' or relative.as_posix()=='validation/REPORT.md':continue
            if relative.parts[0]=='validation' and len(relative.parts)>1 and relative.suffix in {'.txt','.xml','.json'}:continue
            digest.update(relative.as_posix().encode('utf-8')+b'\0')
            try:
                with path.open('rb') as source:
                    for chunk in iter(lambda:source.read(1024*1024),b''):digest.update(chunk)
            except OSError:
                digest.update(b'[unreadable]')
    return 'tree-sha256:'+digest.hexdigest()

def find_maven_executable() -> str | None:
    for name in ('mvn','mvn.cmd','mvn.bat'):
        executable=shutil.which(name)
        if executable:return executable
    wrapper_cache=Path.home()/'.m2'/'wrapper'/'dists'
    if not wrapper_cache.is_dir():return None
    candidates=[]
    for pattern in ('apache-maven-*/**/bin/mvn.cmd','apache-maven-*/**/bin/mvn.bat','apache-maven-*/**/bin/mvn'):
        candidates.extend(path for path in wrapper_cache.glob(pattern) if path.is_file())
    def version_key(path: Path) -> tuple[int,...]:
        match=re.fullmatch(r'apache-maven-(\d+(?:\.\d+)*)',path.parents[2].name)
        return tuple(int(part) for part in match.group(1).split('.')) if match else ()
    return str(max(candidates,key=version_key)) if candidates else None

def tool_version(name: str, args: list[str]) -> dict[str, object]:
    executable=find_maven_executable() if name=='mvn' else shutil.which(name)
    if not executable:return {'available':False}
    try:
        result=subprocess.run([executable,*args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=5)
        version=next((line.strip() for line in result.stdout.splitlines() if line.strip()),'unknown')
        return {'available':True,'path':executable,'version':version,'exitCode':result.returncode}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'available':True,'path':executable,'version':'unknown','error':type(error).__name__}

def environment_versions() -> dict[str, object]:
    try:pytest_version=importlib.metadata.version('pytest')
    except importlib.metadata.PackageNotFoundError:pytest_version='not-installed'
    return {
        'python':{'executable':sys.executable,'version':platform.python_version()},
        'pytest':pytest_version,
        'platform':platform.platform(),
        'java':tool_version('java',['-version']),
        'maven':tool_version('mvn',['-version']),
        'node':tool_version('node',['--version']),
        'npm':tool_version('npm',['--version']),
        'docker':tool_version('docker',['--version']),
    }

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--local',action='store_true');args=parser.parse_args()
    out=ROOT/'validation';out.mkdir(exist_ok=True)
    started_at=utc_now()
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    run_dir=out/'runs'/run_id;run_dir.mkdir(parents=True,exist_ok=False)
    results=[]
    source_id=git_source_id()
    environment=environment_versions()
    env=os.environ.copy();env.update(LOCAL_DEV='true',APP_ORIGIN='http://127.0.0.1:8088',APP_MASTER_KEY=base64.b64encode(os.urandom(32)).decode(),APP_SETUP_TOKEN=secrets.token_urlsafe(36))
    # Never inherit a real node or mail transport configuration into tests.
    for key in list(env):
        if key.startswith(('AGENT_','SMTP_','DATABASE_','MIGRATION_')) or key in ('APP_MASTER_KEY_FILE','APP_SETUP_TOKEN_FILE','TEST_RECIPIENTS','ADMIN_SOURCE_IPS','ADMIN_TRUSTED_PROXY_CIDRS'):env.pop(key,None)
    env['ASTROGATE_VALIDATION_DIR']=str(run_dir)
    def run(name,cmd,cwd=ROOT,timeout=900,artifacts=(),workspace=None):
        executable=find_maven_executable() if cmd[0]=='mvn' else shutil.which(cmd[0]); state='passed';code=None
        if not executable:text=f'BLOCKED: required executable not installed: {cmd[0]}\n';state='blocked'
        else:
            try:
                execution=subprocess.run([executable,*cmd[1:]],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
                code=execution.returncode;text=execution.stdout;state='passed' if code==0 else 'failed'
            except subprocess.TimeoutExpired:text='FAILED: timeout; no pass claimed.\n';state='failed'
        # Suppress ephemeral credentials if third-party tools echo an environment value.
        for key in ('APP_MASTER_KEY','APP_SETUP_TOKEN'):
            text=text.replace(env[key],'[REDACTED]')
        log_path=run_dir/(name+'.txt')
        log_path.write_text(text,encoding='utf-8')
        artifact_paths=[{'path':log_path.relative_to(run_dir).as_posix(),'kind':'combined-output'}]
        for artifact in artifacts:
            artifact_path=Path(artifact).resolve()
            report_files=sorted(artifact_path.rglob('*.xml')) if artifact_path.is_dir() else [artifact_path]
            if not report_files:report_files=[artifact_path]
            for report_file in report_files:
                try:relative_path=report_file.relative_to(run_dir.resolve()).as_posix()
                except ValueError:relative_path=str(report_file)
                artifact_paths.append({'path':relative_path,'kind':'test-report' if report_file.is_file() else 'test-report-directory','exists':report_file.is_file() if report_file.suffix=='.xml' else report_file.exists()})
        step={'name':name,'command':cmd,'status':state,'exitCode':code,'log':log_path.relative_to(run_dir).as_posix(),'artifacts':artifact_paths}
        if workspace is not None:step['workspace']=Path(workspace).resolve().relative_to(run_dir.resolve()).as_posix()
        results.append(step)
        print(f'{name}: {state}',flush=True);return state=='passed'
    def blocked(name,reason):
        log_path=run_dir/(name+'.txt');log_path.write_text(f'BLOCKED: {reason}\n',encoding='utf-8')
        relative_path=log_path.relative_to(run_dir).as_posix()
        results.append({'name':name,'status':'blocked','reason':reason,'exitCode':None,'log':relative_path,'artifacts':[{'path':relative_path,'kind':'combined-output'}]})
    def run_maven(name,goals):
        if not find_maven_executable():
            blocked(name,'Maven is unavailable (PATH and ~/.m2/wrapper/dists were checked)')
            return False
        work_root=run_dir/'maven-work';backend_copy=work_root/'backend'
        try:
            shutil.copytree(ROOT/'backend',backend_copy,ignore=shutil.ignore_patterns('target','.local','.env','*.log'))
        except OSError as error:
            blocked(name,f'could not prepare isolated Maven work copy: {type(error).__name__}')
            return False
        target=backend_copy/'target'
        report_dirs=(target/'surefire-reports',target/'failsafe-reports')
        command=['mvn','-B','-f',str(backend_copy/'pom.xml'),*goals]
        return run(name,command,backend_copy,900,artifacts=report_dirs,workspace=backend_copy)
    junit_xml=run_dir/'python-tests.xml'
    run('python-test-output',[sys.executable,'-m','pytest','agent/tests','tests','-q',f'--junitxml={junit_xml}'],artifacts=(junit_xml,))
    run('java-core-output',['bash','scripts/test_core.sh'])
    run('java-source-parse',['java','scripts/JavaSyntaxCheck.java','backend/src'])
    run('frontend-syntax-output',['node','scripts/check_frontend.cjs'])
    ts=Path(env.get('TYPESCRIPT_PATH',str(ROOT/'frontend/node_modules/typescript')))
    run('frontend-pure-typecheck',['node',str(ts/'lib/tsc.js'),'--noEmit','--strict','--target','ES2022','--module','ESNext','--moduleResolution','Bundler','--lib','ES2022,DOM','frontend/src/api.ts','frontend/src/format.ts','frontend/src/types.ts'])
    run('source-scan',[sys.executable,'scripts/source_scan.py'])
    if not args.local:
        run_maven('maven-verify',['verify'])
        run('frontend-tests',['npm','run','test'],ROOT/'frontend')
        run('frontend-build',['npm','run','build'],ROOT/'frontend')
        docker_ok=run('docker-availability',['docker','info'])
        if docker_ok:
            # New isolated directory/project/volume only. Never run 'down -v' on the user's deployment.
            with tempfile.TemporaryDirectory(prefix='astrogate-smoke-') as tmp:
                clone=Path(tmp)/'source';shutil.copytree(ROOT,clone,ignore=shutil.ignore_patterns('.git','.env','secrets','.local','.pytest_cache','__pycache__','node_modules','target','dist','validation'))
                run('smoke-bootstrap',[sys.executable,'scripts/init_secrets.py','--dev','--root',str(clone)],clone)
                with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
                compose=clone/'compose.yml';compose.write_text(compose.read_text().replace('127.0.0.1:8088:8080',f'127.0.0.1:{port}:8080'))
                cfg=clone/'.env';cfg.write_text(cfg.read_text().replace('http://127.0.0.1:8088',f'http://127.0.0.1:{port}'))
                project='agtest-'+secrets.token_hex(5);command=['docker','compose','--project-name',project]
                try:
                    built=run('compose-build',command+['build'],clone,1800)
                    if built and run('compose-empty-volume-start',command+['up','-d'],clone):run('compose-smoke',[sys.executable,'tests/compose_smoke.py','--base-url',f'http://127.0.0.1:{port}'],clone,150)
                finally:run('compose-isolated-cleanup',command+['down','--volumes','--remove-orphans'],clone)
        else:blocked('compose-build-and-empty-volume-smoke','Docker unavailable; not executed')
    else:
        run_maven('maven-client-ip-test',['-Dtest=ClientIpResolverTest','test'])
    report={
        'runId':run_id,
        'scope':'local-subset' if args.local else 'full-attempt',
        'startedAtUtc':started_at,
        'finishedAtUtc':utc_now(),
        'sourceId':source_id,
        'environment':environment,
        'productionAccepted':False,
        'steps':results,
    }
    (run_dir/'results.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    if any(step['status']!='passed' for step in results):return 2
    print('Requested test scope passed. This does NOT include real-server/provider/SMTP inbox acceptance.')
    return 0
if __name__=='__main__':sys.exit(main())
