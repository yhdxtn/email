"""Real loopback TCP/TLS tests with ephemeral certificates. No production endpoint is contacted."""
from __future__ import annotations
from contextlib import contextmanager
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import ssl
import threading
import uuid
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from agent.server import make_server
from .conftest import request


@pytest.fixture
def certificates(tmp_path):
    now=dt.datetime.now(dt.timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Ephemeral test CA")])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),True)
        .sign(ca_key,hashes.SHA256()))
    root=tmp_path/'tls';root.mkdir()
    (root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for label in ('server','client','other'):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cn=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label)])
        builder=(x509.CertificateBuilder().subject_name(cn).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
                 .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False)
                 .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if label=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False))
        if label=='server':builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
        cert=builder.sign(ca_key,hashes.SHA256())
        (root/f'{label}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root/f'{label}.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        (root/f'{label}.key').chmod(0o600)
    return root


@contextmanager
def running(agent,certificates=None):
    if certificates:
        cert=x509.load_pem_x509_certificate((certificates/'client.pem').read_bytes())
        agent.config.update(tls_cert_file=str(certificates/'server.pem'),tls_key_file=str(certificates/'server.key'),tls_ca_file=str(certificates/'ca.pem'),client_cert_sha256=cert.fingerprint(hashes.SHA256()).hex())
    server=make_server(agent,('127.0.0.1',0),tls=certificates is not None)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield server.server_address[1]
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


def context(root,client='client'):
    ctx=ssl.create_default_context(cafile=str(root/'ca.pem'))
    if client:ctx.load_cert_chain(str(root/f'{client}.pem'),str(root/f'{client}.key'))
    return ctx


def test_real_mtls_and_signed_rpc(agent,certificates):
    with running(agent,certificates) as port:
        conn=http.client.HTTPSConnection('127.0.0.1',port,context=context(certificates),timeout=3)
        headers,raw=request(agent,'mailbox.list')
        conn.request('POST','/rpc/v1',raw,headers);response=conn.getresponse()
        assert response.status==200
        body=json.loads(response.read());assert body['supported'] is True and body['items']==[]
        conn.close()


def test_tls_without_client_cert_rejected(agent,certificates):
    with running(agent,certificates) as port:
        conn=http.client.HTTPSConnection('127.0.0.1',port,context=context(certificates,None),timeout=3)
        headers,raw=request(agent,'health.read')
        with pytest.raises((ssl.SSLError,ConnectionResetError,http.client.RemoteDisconnected)):
            conn.request('POST','/rpc/v1',raw,headers);conn.getresponse().read()
        conn.close()


def test_valid_ca_but_different_client_pin_rejected(agent,certificates):
    with running(agent,certificates) as port:
        conn=http.client.HTTPSConnection('127.0.0.1',port,context=context(certificates,'other'),timeout=3)
        headers,raw=request(agent,'health.read')
        conn.request('POST','/rpc/v1',raw,headers);response=conn.getresponse()
        assert response.status==403 and json.loads(response.read())['code']=='CLIENT_CERT_NOT_BOUND'
        conn.close()


def test_untrusted_server_certificate_rejected(agent,certificates):
    with running(agent,certificates) as port:
        ctx=ssl.create_default_context();ctx.load_cert_chain(str(certificates/'client.pem'),str(certificates/'client.key'))
        conn=http.client.HTTPSConnection('127.0.0.1',port,context=ctx,timeout=3)
        with pytest.raises(ssl.SSLCertVerificationError):conn.request('GET','/')
        conn.close()


@pytest.mark.parametrize('case,status', [('unsigned',401),('path',404),('get',405),('contenttype',415),('oversize',413)])
def test_http_boundary(agent,case,status):
    with running(agent) as port:
        headers,raw=request(agent,'health.read')
        if case=='unsigned':headers.pop('X-Signature')
        if case=='contenttype':headers['Content-Type']='text/plain'
        if case=='oversize':headers['Content-Length']='1000000';raw=b''
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        conn.request('GET' if case=='get' else 'POST','/other' if case=='path' else '/rpc/v1',raw,headers)
        response=conn.getresponse();assert response.status==status
        assert 'no-store' in response.getheader('Cache-Control')
        body=response.read();assert b'Traceback' not in body and b'passwordHash' not in body
        conn.close()


def test_idempotency_across_real_http_requests(agent,password_hash):
    job=str(uuid.uuid4());params={'address':'http@example.test','passwordHash':password_hash,'quotaBytes':1048576}
    outcomes=[]
    with running(agent) as port:
        for _ in range(2):
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            headers,raw=request(agent,'mailbox.create',params,job_id=job)
            conn.request('POST','/rpc/v1',raw,headers);response=conn.getresponse()
            assert response.status==200;outcomes.append(json.loads(response.read()));conn.close()
    assert outcomes[0]==outcomes[1]
    assert agent.node.db.execute('SELECT count(*) FROM mailbox').fetchone()[0]==1
