#!/usr/bin/env python3
"""Small deterministic source scan, NOT a full security audit or entropy-based secret scanner."""
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
SKIP={'.git','.local','.pytest_cache','.venv','venv','.tox','__pycache__','node_modules','target','dist','secrets','validation'}
PATTERNS={
 'private_key_material': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{20}'),
 'aws_access_key': re.compile(r'\bAKIA[A-Z0-9]{16}\b'),
 'github_token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
 'shell_true': re.compile(r'\bshell\s*=\s*True\b'),
}
findings=[]; count=0
for file in ROOT.rglob('*'):
    if not file.is_file() or set(file.relative_to(ROOT).parts)&SKIP: continue
    if file.name=='.env' or (file.suffix in {'.p12','.key','.sqlite','.agbackup'}):
        findings.append((str(file.relative_to(ROOT)),'forbidden_release_file'));continue
    try: text=file.read_text(encoding='utf-8')
    except (UnicodeError,OSError):continue
    count+=1
    for label,pattern in PATTERNS.items():
        if pattern.search(text): findings.append((str(file.relative_to(ROOT)),label))
for path,label in findings: print(f'FAIL {path}: {label}')
print(f'Source scan: {count} text files, {len(findings)} pattern findings. Limited patterns only; not proof of absence of secrets/vulnerabilities.')
sys.exit(bool(findings))
