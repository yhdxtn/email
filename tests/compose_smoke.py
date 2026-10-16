#!/usr/bin/env python3
"""Read-only HTTP smoke against an explicitly supplied loopback control-plane instance."""
import argparse
import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request

def smoke(base:str) -> None:
    url=urllib.parse.urlparse(base)
    if url.scheme!='http' or url.hostname not in ('127.0.0.1','localhost','::1') or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:
        raise ValueError('Only explicit loopback HTTP test instances are accepted.')
    base=base.rstrip('/');opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    for attempt in range(45):
        try:
            with opener.open(base+'/api/v1/setup/status',timeout=3) as response: status=json.load(response)
            assert status['needsSetup'] is True, 'Only a NEW empty database is accepted for this smoke test.'
            assert status['productionAccepted'] is False
            break
        except (urllib.error.URLError,TimeoutError):time.sleep(2)
    else:raise RuntimeError('Control plane never became ready.')
    for route in ('/overview','/mailboxes','/audit/events'):
        try:opener.open(base+'/api/v1'+route,timeout=5)
        except urllib.error.HTTPError as error:assert error.code==401,(route,error.code)
        else:raise AssertionError('Unauthenticated API was accessible: '+route)
    with opener.open(base+'/api/v1/auth/csrf',timeout=5) as response:csrf=json.load(response)
    assert csrf.get('token') and csrf.get('headerName')
    request=urllib.request.Request(base+'/api/v1/setup/initialize',data=b'{}',method='POST',headers={'Content-Type':'application/json'})
    try:opener.open(request,timeout=5)
    except urllib.error.HTTPError as error:assert error.code==403,error.code
    else:raise AssertionError('Missing CSRF was accepted.')
    print('PASS: fresh setup state, three unauthenticated API denials, CSRF bootstrap and missing-CSRF denial. No setup/admin/mail/DNS mutations performed.')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--base-url',required=True);args=parser.parse_args();smoke(args.base_url)
