"""Independent offline verifier: Python standard library + OpenSSL, no vault imports."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def canonical(value): return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(data): return hashlib.sha256(data).hexdigest()


def verify_package(path, trusted_fingerprint, openssl='openssl'):
    if not re.fullmatch('[0-9a-f]{64}', trusted_fingerprint): raise ValueError('Trusted public-key SHA256 fingerprint required')
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix='poco-verify-') as directory:
        members=archive.infolist();names=[m.filename for m in members]
        if len(names)!=len(set(names)) or len(names)>25000:raise ValueError('Duplicate or excessive ZIP entries')
        pattern=r'(case\.json|public\.pem|manifest\.json|manifest\.sig|journal/[0-9]{8}\.json|objects/[0-9a-f]{32}\.enc)'
        if any(not re.fullmatch(pattern,m.filename) or m.file_size>9*1024*1024 or (m.external_attr>>16)&0o170000==0o120000 for m in members):raise ValueError('Unsafe ZIP member')
        if sum(m.file_size for m in members)>550*1024*1024:raise ValueError('Package exceeds verification limit')
        manifest_raw=archive.read('manifest.json');manifest=json.loads(manifest_raw)
        if manifest['format']!='PocoQA-package-v1' or canonical(manifest)!=manifest_raw:raise ValueError('Unknown/noncanonical manifest')
        if set(names)!=set(manifest['files'])|{'manifest.json','manifest.sig'}:raise ValueError('Manifest file set mismatch')
        folder=Path(directory);pub=folder/'public.pem';pub.write_bytes(archive.read('public.pem'))
        public_der=subprocess.run([openssl,'pkey','-pubin','-in',str(pub),'-outform','DER'],check=True,capture_output=True).stdout
        # RFC 8410 SubjectPublicKeyInfo prefix for Ed25519, followed by the raw 32-byte key.
        if not public_der.startswith(bytes.fromhex('302a300506032b6570032100')) or len(public_der)!=44:raise ValueError('Expected Ed25519 key')
        fingerprint=digest(public_der[-32:])
        if fingerprint!=trusted_fingerprint or manifest['signer_sha256']!=fingerprint:raise ValueError('Signer not trusted')
        def signature(data,sig):
            source=folder/'input';signed=folder/'signature';source.write_bytes(data);signed.write_bytes(sig)
            result=subprocess.run([openssl,'pkeyutl','-verify','-pubin','-inkey',str(pub),'-rawin','-in',str(source),'-sigfile',str(signed)],capture_output=True,timeout=10)
            if result.returncode:raise ValueError('Invalid Ed25519 signature')
        signature(manifest_raw,archive.read('manifest.sig'))
        for name,expected in manifest['files'].items():
            hasher=hashlib.sha256();size=0
            with archive.open(name) as source:
                while block:=source.read(65536):hasher.update(block);size+=len(block)
            if hasher.hexdigest()!=expected['sha256'] or size!=expected['bytes']:raise ValueError('Artifact hash mismatch: '+name)
        case=json.loads(archive.read('case.json'))
        if case['case_id']!=manifest['case_id'] or case['signer_sha256']!=fingerprint:raise ValueError('Case identity mismatch')
        journal=sorted(n for n in names if n.startswith('journal/'));previous='0'*64
        if len(journal)!=manifest['events']:raise ValueError('Journal count mismatch')
        for seq,name in enumerate(journal,1):
            if name!=f'journal/{seq:08d}.json':raise ValueError('Custody gap')
            event=json.loads(archive.read(name));sig=base64.b64decode(event.pop('signature'),validate=True);expected=event.pop('digest')
            if event['seq']!=seq or event['case_id']!=case['case_id'] or event['previous']!=previous or digest(canonical(event))!=expected:raise ValueError('Invalid custody chain')
            signature(bytes.fromhex(expected),sig);previous=expected
        if previous!=manifest['head']:raise ValueError('Custody head mismatch')
        return {'valid':True,'signer_trusted':True,'case_id':case['case_id'],'events':len(journal),'files':len(manifest['files']),
                'head':previous,'signer_sha256':fingerprint,'manifest_sha256':digest(manifest_raw),
                'plaintext_verified':False,'limitation':'Ciphertext integrity and signatures verified. Decryption requires separately held keys; source truth and human identity are not certified.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('package');parser.add_argument('--trusted-key',required=True)
    args=parser.parse_args();print(json.dumps(verify_package(args.package,args.trusted_key),indent=2))
