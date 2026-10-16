#!/usr/bin/env python3
"""Create a NEW local deployment configuration only. Never connect to a mail server or DNS."""
from __future__ import annotations
import argparse
import base64
import os
from pathlib import Path
import secrets
from urllib.parse import urlparse


def initialize(root: Path,dev:bool=False,origin:str='https://admin.example.test') -> None:
    root=root.resolve();root.mkdir(parents=True,exist_ok=True)
    if (root/'.env').exists() or (root/'secrets').exists():
        raise ValueError('Refusing to overwrite existing .env or secrets. Back them up and manage changes explicitly.')
    target='http://127.0.0.1:8088' if dev else origin
    parsed=urlparse(target)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/') or (not dev and parsed.scheme!='https') or not parsed.hostname:
        raise ValueError('Production origin must be an HTTPS origin without credentials, path, query or fragment.')
    current_uid=os.getuid() if hasattr(os,'getuid') else 10001
    current_gid=os.getgid() if hasattr(os,'getgid') else 10001
    uid=10001 if current_uid==0 else current_uid;gid=10001 if current_uid==0 else current_gid
    directory=root/'secrets';directory.mkdir(mode=0o700)
    values={name:secrets.token_urlsafe(36) for name in ['postgres-password','database-password','migration-password','setup-token','agent-keystore-password']}
    values.update({name:base64.b64encode(os.urandom(32)).decode() for name in ['master-key','agent-signing-key']})
    values['smtp-password']=''
    for name,value in values.items():
        path=directory/name
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(value+'\n')
        if hasattr(os,'getuid') and os.getuid()==0:os.chown(path,uid,gid)
    (directory/'agent-client').mkdir(mode=0o700)
    if hasattr(os,'getuid') and os.getuid()==0:
        os.chown(directory,uid,gid);os.chown(directory/'agent-client',uid,gid)
    fd=os.open(root/'.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        stream.write(f'LOCAL_DEV={str(dev).lower()}\nAPP_ORIGIN={target.rstrip("/")}\nCONTROL_UID={uid}\nCONTROL_GID={gid}\nSMTP_HOST=\nSMTP_USERNAME=\nSMTP_ALLOWED_FROM=\nTEST_RECIPIENTS=\nFORWARD_ALLOWED_DOMAINS=\nAGENT_URL=\nAGENT_INSTANCE_ID=\n')
    print('Created deployment files; no external changes made. Setup token: secrets/setup-token (contents not printed).')
    print('Agent, SMTP and DNS API integrations remain unconfigured. Production requires an HTTPS reverse proxy.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--dev',action='store_true');parser.add_argument('--origin',default='https://admin.example.test');parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);args=parser.parse_args()
    try:initialize(args.root,args.dev,args.origin)
    except ValueError as error:parser.exit(2,str(error)+'\n')
