#!/usr/bin/env python3
"""Offline enrollment bundle generation; does not connect to any server or change DNS."""
from __future__ import annotations
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def generate(out:Path,dns:str,ip:str,password:bytes) -> None:
    if out.exists():raise ValueError('Refusing to overwrite existing PKI output.')
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]',dns) or '..' in dns:raise ValueError('Use a lowercase DNS name, not a URL.')
    address=ipaddress.ip_address(ip)
    if len(password)<24:raise ValueError('PKCS12 password must be independently generated, at least 24 bytes.')
    out.mkdir(parents=True,mode=0o700);now=dt.datetime.now(dt.timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Astrogate private agent CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),True).sign(ca_key,hashes.SHA256()))
    def save(name:str,value:bytes):
        fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(value)
    save('ca.pem',ca.public_bytes(serialization.Encoding.PEM))
    save('OFFLINE-CA-PRIVATE.key',ca_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    for label in ('server','client'):
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,dns if label=='server' else 'Astrogate control plane')])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if label=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False))
        if label=='server':cert=cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns),x509.IPAddress(address)]),False)
        cert=cert.sign(ca_key,hashes.SHA256())
        save(label+'.pem',cert.public_bytes(serialization.Encoding.PEM))
        if label=='server':save('server.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        else:
            save('client.p12',pkcs12.serialize_key_and_certificates(b'control-client',key,cert,[ca],serialization.BestAvailableEncryption(password)))
            save('client-cert-sha256.txt',(cert.fingerprint(hashes.SHA256()).hex()+'\n').encode())
    # Use keytool below for a Java truststore: a certificate-only PKCS12 serialized with other
    # libraries is not always interpreted as a trustedCertEntry by Java. No fake truststore generated.
    save('README.txt',b'Use keytool -importcert -storetype PKCS12 -alias agent-ca -file ca.pem -keystore trust.p12. Supply the SAME independently generated keystore password. Keep OFFLINE-CA-PRIVATE.key offline. Server cert renewal and client pin rotation are manual.\n')
    print('PKI generated locally. No secrets printed. Certificate lifetime: 90 days. Keep CA private key offline.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--dns',required=True);parser.add_argument('--ip',required=True);parser.add_argument('--password-file',type=Path,required=True);args=parser.parse_args()
    try:generate(args.out,args.dns,args.ip,args.password_file.read_bytes().strip())
    except ValueError as error:parser.exit(2,str(error)+'\n')
