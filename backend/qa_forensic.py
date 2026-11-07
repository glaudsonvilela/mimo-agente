"""Local encrypted evidence vault. No networking, scanners or HTML execution."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import stat
import tempfile
import time
import uuid
import zipfile

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROOT = Path(__file__).resolve().parent
VERSION = '1.0'
MAX_OBJECT = 8 * 1024 * 1024
MAX_EVENTS = 12000
LIMITATIONS = [
    'Application-level capture: HTTP transfer framing, TLS wire bytes and screenshots are not acquired.',
    'Clock is the device clock, not an independent trusted timestamp.',
    'Signatures authenticate the local key, not a verified human identity or truth of a claim.',
    'Private keys and local anchors share the Android account; compromise of that account is outside this trust boundary.',
    'Custody records cover operations through this tool; direct OS reads cannot be audited by this application.',
    'Local backup is a separate copy, not an independent physical device. Keep an external copy and key recovery material separately.',
]


class IntegrityError(ValueError): pass
class StorageLimit(OSError): pass


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(path):
    hasher=hashlib.sha256()
    with open(path,'rb') as stream:
        while block:=stream.read(65536):hasher.update(block)
    return hasher.hexdigest()
def b64(data): return base64.b64encode(data).decode()
def unb64(value): return base64.b64decode(value, validate=True)


def private_dir(path):
    path = Path(path)
    if path.is_symlink(): raise IntegrityError('Symlink not allowed')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.geteuid(): raise IntegrityError('Wrong directory owner')
    path.chmod(0o700)
    return path


def read_regular(path, maximum=MAX_OBJECT + 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum: raise IntegrityError('Invalid file or size')
        with os.fdopen(fd, 'rb', closefd=False) as stream: return stream.read(maximum + 1)
    finally: os.close(fd)


def publish_temp(source, destination, replace=False):
    # Android forbids hard links. Serialize writers inside the private directory,
    # check nonexistence under this lock, then publish with an atomic rename.
    destination=Path(destination)
    fd=os.open(destination.parent/'.write.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        if destination.is_symlink():raise IntegrityError('Symlink not allowed')
        if not replace and os.path.lexists(destination):raise FileExistsError(str(destination))
        os.replace(source,destination)
        directory=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def atomic(path, data, replace=False, mode=0o600):
    path = Path(path)
    fd, temp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        publish_temp(temp,path,replace)
    finally:
        if os.path.exists(temp): os.unlink(temp)


class Keys:
    def __init__(self, directory, create=True):
        self.directory = private_dir(directory)
        self.path = self.directory / 'keys.json'
        if not self.path.exists() and create:
            signer = Ed25519PrivateKey.generate()
            private = signer.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            try: atomic(self.path, encoded({'aes': b64(AESGCM.generate_key(bit_length=256)), 'ed25519': b64(private)}))
            except FileExistsError: pass
        if self.path.stat().st_mode & 0o077: raise IntegrityError('Key file requires permission 0600')
        data = json.loads(read_regular(self.path, 4096))
        self.aes = AESGCM(unb64(data['aes']))
        self.signer = Ed25519PrivateKey.from_private_bytes(unb64(data['ed25519']))
        self.public = self.signer.public_key()
        self.pem = self.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint = sha(self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def seal(self, data, aad):
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, data, aad.encode())

    def open(self, data, aad): return self.aes.decrypt(data[:12], data[12:], aad.encode())

    def backup(self, path, password):
        if len(password) < 16: raise ValueError('Recovery password must have at least 16 bytes')
        salt = os.urandom(16); nonce = os.urandom(12)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)
        data = AESGCM(key).encrypt(nonce, read_regular(self.path, 4096), b'PocoQA-keys-v1')
        atomic(path, encoded({'format': 'PocoQA-keys-v1', 'salt': b64(salt), 'nonce': b64(nonce), 'data': b64(data)}))

    @staticmethod
    def restore(backup, directory, password):
        obj = json.loads(read_regular(backup, 16384))
        if obj['format'] != 'PocoQA-keys-v1': raise IntegrityError('Unknown key format')
        key = Scrypt(salt=unb64(obj['salt']), length=32, n=2**15, r=8, p=1).derive(password)
        plain = AESGCM(key).decrypt(unb64(obj['nonce']), unb64(obj['data']), b'PocoQA-keys-v1')
        atomic(private_dir(directory) / 'keys.json', plain)
        return Keys(directory, create=False)


def redact(text, secrets=()):
    import urllib.parse
    text = str(text)
    for value in sorted(set(secrets), key=len, reverse=True):
        if value:
            for form in (value, urllib.parse.quote(value, safe=''), urllib.parse.quote_plus(value)):
                text = text.replace(form, '[REDACTED]')
    text = re.sub(r'(?i)(authorization\s*[:=]\s*)[^\r\n<]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)((?:password|passwd|token|secret|session|cookie|api[_-]?key)\s*[=:]\s*)[^\s&<>;,]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(\bvalue\s*=\s*)(["\x27]).*?\2', r'\1"[REDACTED]"', text)
    return text


def clock_record(previous=None):
    wall = time.time_ns(); mono = time.monotonic_ns()
    try: boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError: boot = 'unavailable'
    result = {'utc': datetime.fromtimestamp(wall / 1e9, timezone.utc).isoformat(), 'wall_ns': wall,
              'monotonic_ns': mono, 'boot_id': boot, 'utc_offset_seconds': int(datetime.now().astimezone().utcoffset().total_seconds()),
              'source': 'device_clock', 'independent_timestamp': False}
    if previous:
        if previous['boot_id'] != boot: result['warning'] = 'boot_changed; monotonic clocks not comparable'
        else:
            delta = ((wall - previous['wall_ns']) - (mono - previous['monotonic_ns'])) / 1e9
            result['wall_monotonic_delta_seconds'] = round(delta, 6)
            if abs(delta) > 2: result['warning'] = 'wall_clock_jump'
    return result


class Case:
    def __init__(self, path, key_dir=None, anchors=None, scope=None, actor=None, max_bytes=128*1024*1024, minimum_free=64*1024*1024):
        self.path = private_dir(path); self.id = self.path.name
        if not re.fullmatch(r'[0-9a-f]{32}', self.id): raise ValueError('Case ID must be 32 hex characters')
        self.keys = Keys(key_dir or ROOT / 'forensic-keys')
        self.anchors = private_dir(anchors or ROOT / 'forensic-anchors')
        self.actor = actor or 'local-uid-' + str(os.geteuid())
        if not isinstance(self.actor, str) or not 1 <= len(self.actor) <= 120: raise ValueError('Invalid actor')
        self.max_bytes = int(max_bytes); self.minimum_free = int(minimum_free)
        if not 1024 <= self.max_bytes <= 512*1024*1024 or not 0 <= self.minimum_free <= 1024**3: raise ValueError('Storage policy outside limits')
        self.journal = private_dir(self.path / 'journal'); self.objects = private_dir(self.path / 'objects')
        self.meta = self.path / 'case.json'; self.anchor = self.anchors / (self.id + '.json')
        with self.lock():
            if not self.meta.exists():
                if scope is None: raise IntegrityError('Case not initialized')
                atomic(self.meta, encoded({'format': 'PocoQA-case-v1', 'case_id': self.id, 'signer_sha256': self.keys.fingerprint,
                                         'encryption': 'AES-256-GCM', 'signature': 'Ed25519'}))
                atomic(self.path / 'public.pem', self.keys.pem)
                self._append('case_created', {'scope': scope, 'tool': 'PocoQA forensic', 'version': VERSION,
                    'python': platform.python_version(), 'cryptography': cryptography.__version__, 'openssl':ssl.OPENSSL_VERSION, 'platform': platform.system(),
                    'source_hashes': {p.name: sha(p.read_bytes()) for p in ROOT.glob('qa_*.py')}, 'limitations': LIMITATIONS}, [])
            elif json.loads(read_regular(self.meta))['signer_sha256'] != self.keys.fingerprint:
                raise IntegrityError('Case belongs to another key')
            events = self._events()
            if not events and not self.anchor.exists() and scope is not None:
                self._append('case_created',{'scope':scope,'version':VERSION,'initialization_recovered':True,'limitations':LIMITATIONS},[])
                events=self._events()
            self._check_anchor(events)
            referenced = {e['payload']['artifact']['path'] for e in events if 'artifact' in e['payload']}
            for path in sorted(self.objects.iterdir()):
                if path.name.startswith('.pending-') or path.name=='.write.lock': continue
                relative = 'objects/' + path.name
                if relative not in referenced:
                    cipher = read_regular(path); plain = self.keys.open(cipher, self.id + ':' + path.stem)
                    detail = {'id': path.stem, 'path': relative, 'cipher_sha256': sha(cipher), 'sha256': sha(plain),
                              'bytes': len(plain), 'kind': 'recovered_uncommitted', 'metadata': {'association': 'unknown; interrupted write'}}
                    self._append('recovered_uncommitted_artifact', {'artifact': detail}, self._events())
            events = self._events(); self._check_objects(events)
            self._anchor(events)

    @contextmanager
    def lock(self):
        fd = os.open(self.path / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX); yield
        finally: fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)

    def _events(self):
        expected={'format':'PocoQA-case-v1','case_id':self.id,'signer_sha256':self.keys.fingerprint,'encryption':'AES-256-GCM','signature':'Ed25519'}
        if json.loads(read_regular(self.meta))!=expected or read_regular(self.path/'public.pem')!=self.keys.pem:raise IntegrityError('Case metadata modified')
        entries = sorted(self.journal.glob('*.json'))
        if len(entries) > MAX_EVENTS: raise IntegrityError('Too many custody events')
        previous = '0'*64; result = []
        for number, path in enumerate(entries, 1):
            if path.name != f'{number:08d}.json': raise IntegrityError('Custody sequence gap')
            envelope = json.loads(read_regular(path, 256*1024))
            signature = unb64(envelope.pop('signature')); digest = envelope.pop('digest')
            if envelope['seq'] != number or envelope['case_id'] != self.id or envelope['previous'] != previous or sha(encoded(envelope)) != digest:
                raise IntegrityError('Custody chain modified')
            self.keys.public.verify(signature, bytes.fromhex(digest))
            payload = json.loads(self.keys.open(unb64(envelope['sealed']), self.id + ':event:' + str(number)))
            result.append({'seq': number, 'digest': digest, 'payload': payload}); previous = digest
        return result

    def _check_anchor(self, events):
        if not self.anchor.exists():
            raise IntegrityError('External anchor missing; restore an anchored backup')
        anchor = json.loads(read_regular(self.anchor, 8192)); signature = unb64(anchor.pop('signature'))
        self.keys.public.verify(signature, encoded(anchor))
        if anchor['case_id'] != self.id or anchor['count'] > len(events): raise IntegrityError('Custody rollback detected')
        if anchor['count'] and events[anchor['count']-1]['digest'] != anchor['head']: raise IntegrityError('Anchor mismatch')

    def _anchor(self, events):
        record = {'case_id': self.id, 'count': len(events), 'head': events[-1]['digest'], 'signer_sha256': self.keys.fingerprint}
        record['signature'] = b64(self.keys.signer.sign(encoded(record)))
        atomic(self.anchor, encoded(record), replace=True)

    def _check_objects(self, events):
        for event in events:
            item = event['payload'].get('artifact')
            if item:
                if not re.fullmatch(r'objects/[0-9a-f]{32}\.enc', item['path']): raise IntegrityError('Invalid artifact path')
                cipher = read_regular(self.path / item['path'])
                if sha(cipher) != item['cipher_sha256']: raise IntegrityError('Artifact ciphertext modified')
                plain = self.keys.open(cipher, self.id + ':' + item['id'])
                if sha(plain) != item['sha256'] or len(plain) != item['bytes']: raise IntegrityError('Artifact content modified')

    def _space(self, amount):
        total = sum(p.stat().st_size for folder in (self.journal, self.objects) for p in folder.iterdir())
        if total + amount > self.max_bytes: raise StorageLimit('Case storage quota reached; stop acquisition and resume after review')
        if shutil.disk_usage(self.path).free < self.minimum_free + amount: raise StorageLimit('Insufficient free storage; no evidence overwritten')

    def _append(self, action, detail, events):
        if len(events) >= MAX_EVENTS: raise StorageLimit('Custody event limit reached')
        number = len(events) + 1
        payload = {'action': action, 'actor': self.actor, 'actor_identity_verified': False,
                   'clock': clock_record(events[-1]['payload']['clock'] if events else None), **detail}
        sealed = self.keys.seal(encoded(payload), self.id + ':event:' + str(number))
        envelope = {'case_id': self.id, 'seq': number, 'previous': events[-1]['digest'] if events else '0'*64, 'sealed': b64(sealed)}
        digest = sha(encoded(envelope)); envelope.update(digest=digest, signature=b64(self.keys.signer.sign(bytes.fromhex(digest))))
        self._space(len(encoded(envelope)) + 4096)
        atomic(self.journal / f'{number:08d}.json', encoded(envelope), mode=0o400)
        events = events + [{'seq': number, 'digest': digest, 'payload': payload}]
        self._anchor(events)
        return number

    def event(self, action, **detail):
        with self.lock():
            events = self._events(); self._check_anchor(events)
            return self._append(action, detail, events)

    def put(self, data, kind, metadata=None, derived_from=None):
        if not isinstance(data, bytes) or len(data) > MAX_OBJECT: raise ValueError('Artifact must be bytes, at most 8 MiB')
        with self.lock():
            events = self._events(); self._check_anchor(events)
            ident = uuid.uuid4().hex; cipher = self.keys.seal(data, self.id + ':' + ident)
            metadata = metadata or {}
            if len(encoded(metadata)) > 32768: raise ValueError('Metadata too large')
            if derived_from and derived_from not in {e['payload'].get('artifact', {}).get('id') for e in events}: raise ValueError('Unknown source artifact')
            self._space(len(cipher) + len(encoded(metadata))*2 + 16384)
            relative = 'objects/' + ident + '.enc'; atomic(self.path / relative, cipher, mode=0o400)
            item = {'id': ident, 'path': relative, 'kind': kind, 'bytes': len(data), 'sha256': sha(data),
                    'cipher_sha256': sha(cipher), 'metadata': metadata, 'derived_from': derived_from}
            self._append('artifact_acquired' if not derived_from else 'artifact_derived', {'artifact': item}, events)
            return ident

    def artifacts(self):
        return [e['payload']['artifact'] for e in self._events() if 'artifact' in e['payload']]

    def _read(self, item):
        cipher = read_regular(self.path / item['path'])
        if sha(cipher) != item['cipher_sha256']: raise IntegrityError('Artifact modified')
        plain = self.keys.open(cipher, self.id + ':' + item['id'])
        if sha(plain) != item['sha256']: raise IntegrityError('Plaintext hash mismatch')
        return plain

    def verify(self, record=True):
        with self.lock():
            events = self._events(); self._check_anchor(events); self._check_objects(events)
            pending = [str(p.relative_to(self.path)) for folder in (self.path, self.objects, self.journal) for p in folder.glob('.pending-*')]
            result = {'valid': True, 'case_id': self.id, 'events': len(events), 'artifacts': sum('artifact' in e['payload'] for e in events),
                      'head': events[-1]['digest'], 'signer_sha256': self.keys.fingerprint, 'interrupted_temporary_files': pending}
            if record: self._append('integrity_verified', {'result': result}, events)
            return result

    def capture_response(self, response, request_id, context, secrets=()):
        import http.cookies
        known = set(secrets)
        for key, value in response.get('forensic_headers', []):
            if key.lower() == 'set-cookie':
                jar = http.cookies.SimpleCookie(); jar.load(value); known.update(item.value for item in jar.values())
        meta = {'request_id': request_id, 'url': redact(response['url'], known), 'method': 'GET', 'status': response['status'],
                'acquisition_timing':response.get('acquisition_timing'),
                'peer': response['peer'], 'tls': response.get('tls'), 'truncated': response['truncated'],
                'capture': 'HTTP entity bytes after transfer decoding; no request credentials or TLS wire bytes', 'context': context or {}}
        body = self.put(response['body'], 'http_body', meta)
        headers = self.put(encoded(response.get('forensic_headers', [])), 'http_response_headers', {'body_id': body, 'request_id': request_id})
        preview = redact(response['body'].decode('utf-8', 'replace'), known)[:262144].encode()
        self.put(preview, 'redacted_preview', {'rule': 'known session values, credential patterns and HTML value attributes; review before sharing'}, derived_from=body)
        return {'body_id': body, 'headers_id': headers}

    def capture_dom(self, snapshot, request_id, secrets=()):
        data = snapshot['html'].encode(); truncated = bool(snapshot.get('truncated')) or len(data) > 524288
        source = self.put(data[:524288], 'rendered_dom', {'url': redact(snapshot['url'], secrets), 'step': snapshot['step'],
            'request_id': request_id, 'truncated': truncated, 'capture': 'DOM serialization; not the original HTTP body'})
        self.put(redact(data[:524288].decode('utf-8', 'replace'), secrets).encode(), 'redacted_preview', {'rule': 'session and form-value redaction'}, derived_from=source)
        return source

    def report(self, report):
        items = self.artifacts(); by_request = {}
        for item in items:
            if item['kind'] == 'http_body': by_request.setdefault(item['metadata']['request_id'], []).append(item['id'])
        conclusions = []
        for finding in report.get('hypotheses', []):
            ids = sorted({ident for request in finding['evidence_ids'] for ident in by_request.get(request, [])})
            conclusions.append({'classification': 'hypothesis', 'statement': finding['hypothesis'], 'status': finding['status'], 'evidence_ids': ids,
                                'limitation': 'Repeated observation does not establish exploitability'})
        for item in items:
            if item['kind'] == 'http_body': conclusions.append({'classification': 'fact', 'statement': 'Captured HTTP status '+str(item['metadata']['status']), 'evidence_ids': [item['id']]})
        conclusions.append({'classification': 'unknown', 'statement': 'Undiscovered routes, server-side activity and uncollected content remain unknown', 'evidence_ids': []})
        analysis = {'analysis_type': 'deterministic', 'model': None, 'model_version': None, 'configuration': {'rules_version': VERSION}, 'conclusions': conclusions}
        self.put(encoded(report), 'crawl_report', {'format': 'json'})
        self.add_analysis(analysis)

    def add_analysis(self, data):
        if data.get('analysis_type') not in ('deterministic', 'human', 'model'): raise ValueError('Analysis type required')
        def check_configuration(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if re.search(r'password|passwd|secret|token|credential|api.?key|authorization|cookie',str(key),re.I):raise ValueError('Credentials are not permitted in analysis configuration')
                    check_configuration(item)
            elif isinstance(value,list):
                for item in value:check_configuration(item)
        check_configuration(data.get('configuration',{}))
        if data['analysis_type'] == 'model' and not all(data.get(key) for key in ('model', 'model_version', 'configuration')):
            raise ValueError('Model, version and configuration required')
        known = {a['id'] for a in self.artifacts()}
        conclusions = data.get('conclusions')
        if not isinstance(conclusions, list) or len(conclusions) > 2000: raise ValueError('Invalid conclusions')
        for item in conclusions:
            kind = item.get('classification'); ids = item.get('evidence_ids', [])
            if kind not in ('fact','hypothesis','unknown') or not isinstance(item.get('statement'), str): raise ValueError('Invalid claim')
            if not isinstance(ids, list) or not set(ids) <= known or kind != 'unknown' and not ids: raise ValueError('Claim must reference existing evidence')
        return self.put(encoded(data), 'analysis', {'references_validated': True, 'claim_truth_automatically_verified': False})

    def import_log(self, path, source):
        if not isinstance(source, str) or not 1 <= len(source) <= 200: raise ValueError('Source description required')
        data = read_regular(path, MAX_OBJECT)
        if len(data) > MAX_OBJECT: raise ValueError('Log too large')
        rows = []
        for index, line in enumerate(data.decode('utf-8', 'replace').splitlines(), 1):
            if index > 10000: raise ValueError('Log exceeds 10000 lines')
            try:
                value = json.loads(line); stamp = value.get('timestamp')
                when = datetime.fromisoformat(stamp.replace('Z', '+00:00')) if isinstance(stamp, str) else None
                rows.append({'line': index, 'event_utc': when.astimezone(timezone.utc).isoformat() if when and when.tzinfo else None,
                             'time_assurance': 'operator_log_unverified' if when and when.tzinfo else 'missing_or_ambiguous_timezone',
                             'record': value})
            except (ValueError, AttributeError): rows.append({'line': index, 'event_utc': None, 'time_assurance': 'unparsed', 'record': line})
        original = self.put(data, 'imported_log', {'source': source, 'origin_authenticity_verified': False, 'filename': Path(path).name})
        self.put(encoded(rows), 'normalized_log', {'format': 'jsonl-normalization-v1', 'lines': len(rows)}, derived_from=original)
        return original

    def timeline(self):
        events = self._events()
        result = [{'seq': e['seq'], 'action': e['payload']['action'], 'actor': e['payload']['actor'], 'clock': e['payload']['clock'],
                   'artifact_id': e['payload'].get('artifact', {}).get('id')} for e in events]
        for item in self.artifacts():
            if item['kind'] == 'normalized_log':
                for row in json.loads(self._read(item)):
                    result.append({'source_artifact': item['id'], 'line': row['line'], 'event_utc': row['event_utc'], 'time_assurance': row['time_assurance']})
        return result

    def extract(self, ident, destination):
        item=next((a for a in self.artifacts() if a['id']==ident),None)
        if item is None:raise ValueError('Unknown artifact')
        self.event('artifact_access',artifact_id=ident,purpose='explicit_plaintext_export',output_name=Path(destination).name)
        atomic(destination,self._read(item))
        return {'artifact_id':ident,'sha256':item['sha256'],'output':str(destination),'sensitive_plaintext':True}

    def derive_redaction(self, ident, values):
        if not isinstance(values,list) or not values or len(values)>100 or not all(isinstance(v,str) and 1<=len(v)<=4096 for v in values):raise ValueError('Literal redaction list required')
        item=next((a for a in self.artifacts() if a['id']==ident),None)
        if item is None:raise ValueError('Unknown artifact')
        original=self._read(item);derived=redact(original.decode('utf-8','replace'),values).encode()
        return self.put(derived,'redacted_preview',{'rule':'literal values and standard credential patterns','rules_sha256':sha(encoded(values)),
                       'source_encoding':'UTF-8 with replacement','original_sha256':item['sha256']},derived_from=ident)

    def review(self, output):
        self.verify(record=False)
        self.event('offline_review', output_name=Path(output).name)
        items = self.artifacts()
        pieces = ['<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;; sandbox"><title>Revisão offline</title><h1>Revisão offline — '+self.id+'</h1>',
                  '<p>Conteúdo apresentado como texto. Sem scripts, imagens remotas ou navegação. Prévia com redação automática; revise antes de compartilhar.</p>']
        for item in items:
            pieces.append('<h2>'+html.escape(item['kind']+' · '+item['id'])+'</h2><pre>'+html.escape(json.dumps(item['metadata'], ensure_ascii=False, indent=2))+'</pre>')
            if item['kind'] in ('redacted_preview', 'analysis'):
                pieces.append('<pre>'+html.escape(redact(self._read(item).decode('utf-8', 'replace')))+'</pre>')
        pieces.append('<h2>Linha do tempo</h2><pre>'+html.escape(json.dumps(self.timeline(), ensure_ascii=False, indent=2))+'</pre></html>')
        result = ''.join(pieces).encode()
        atomic(output, result)
        self.put(result, 'offline_review', {'output_name': Path(output).name, 'active_content': False})
        return {'path': str(output), 'sha256': sha(result), 'bytes': len(result)}

    def export(self, destination, purpose='export', recipient='operator'):
        destination = Path(destination)
        if destination.exists(): raise FileExistsError('Never overwrite an evidence export')
        with self.lock():
            events = self._events(); self._check_anchor(events); self._check_objects(events)
            self._append('package_export', {'purpose': purpose, 'recipient': recipient, 'output_name': destination.name}, events)
            events = self._events()
            files = [self.meta, self.path/'public.pem'] + sorted(self.journal.glob('*.json')) + sorted(self.objects.glob('*.enc'))
            manifest = {'format': 'PocoQA-package-v1', 'case_id': self.id, 'signer_sha256': self.keys.fingerprint,
                        'events': len(events), 'head': events[-1]['digest'], 'limitations': LIMITATIONS,
                        'files': {str(p.relative_to(self.path)): {'sha256': sha(read_regular(p)), 'bytes': p.stat().st_size} for p in files}}
            raw = encoded(manifest); signature = self.keys.signer.sign(raw)
            total = sum(p.stat().st_size for p in files)
            if shutil.disk_usage(destination.parent).free < self.minimum_free + total + 65536: raise StorageLimit('No room for export')
            fd, temp = tempfile.mkstemp(prefix='.pending-', dir=destination.parent)
            try:
                os.fchmod(fd, 0o600); os.close(fd)
                with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_STORED) as archive:
                    for p in files: archive.write(p, str(p.relative_to(self.path)))
                    archive.writestr('manifest.json', raw); archive.writestr('manifest.sig', signature)
                with open(temp, 'rb') as stream: os.fsync(stream.fileno())
                publish_temp(temp, destination)
            finally:
                if os.path.exists(temp): os.unlink(temp)
            receipt = {'case_id': self.id, 'package_sha256': file_sha(destination), 'manifest_sha256': sha(raw),
                       'signer_sha256': self.keys.fingerprint, 'events': len(events), 'head': events[-1]['digest']}
            self._append('package_export_completed', receipt, self._events())
            return receipt

    def summary(self):
        checked = self.verify()
        return {'case_id': self.id, 'path': str(self.path), 'integrity': checked, 'limitations': LIMITATIONS}

    def text_summary(self):
        self.verify();self.event('analysis_review')
        analyses=[a for a in self.artifacts() if a['kind']=='analysis']
        if not analyses:return 'Caso '+self.id+': nenhuma análise registrada.'
        analysis=json.loads(self._read(analyses[-1]))
        lines=['Caso '+self.id,'Análise: '+analysis['analysis_type']+'; modelo: '+str(analysis.get('model'))]
        for claim in analysis['conclusions'][:25]:
            lines.append(claim['classification']+': '+claim['statement']+' · evidências: '+', '.join(claim['evidence_ids']))
        return '\n'.join(lines)


def locate(ident):
    if not re.fullmatch(r'[0-9a-f]{32}', ident): raise ValueError('Invalid case ID')
    found = list((ROOT/'projects').glob('*/cases/'+ident))
    if len(found) != 1: raise ValueError('Case not found')
    return Case(found[0])


def restore_package(package, destination, key_dir, anchors, trusted_fingerprint):
    from qa_verify import verify_package
    checked=verify_package(package,trusted_fingerprint)
    destination=Path(destination)
    if destination.exists() or destination.name!=checked['case_id']:raise ValueError('Restore requires a new directory named after the case ID')
    keys=Keys(key_dir,create=False)
    if keys.fingerprint!=trusted_fingerprint:raise IntegrityError('Recovery key mismatch')
    anchors=private_dir(anchors);anchor=anchors/(destination.name+'.json')
    if anchor.exists():raise IntegrityError('Existing anchor must not be overwritten by an older backup')
    private_dir(destination)
    with zipfile.ZipFile(package) as archive:
        manifest=json.loads(archive.read('manifest.json'))
        for name in manifest['files']:
            target=destination/name;private_dir(target.parent);atomic(target,archive.read(name),mode=0o400)
    record={'case_id':destination.name,'count':checked['events'],'head':checked['head'],'signer_sha256':keys.fingerprint}
    record['signature']=b64(keys.signer.sign(encoded(record)));atomic(anchor,encoded(record))
    case=Case(destination,key_dir,anchors)
    case.event('backup_restored',package_sha256=file_sha(package),manifest_sha256=checked['manifest_sha256'])
    return case.verify()


def dispatch(prompt):
    text = prompt.strip().lower()
    if text == 'casos':
        cases = sorted((ROOT/'projects').glob('*/cases/*/case.json'), key=lambda p:p.stat().st_mtime, reverse=True)[:20]
        return 'Casos locais:\n'+'\n'.join(p.parent.name for p in cases) if cases else 'Nenhum caso coletado ainda. Use mapear com uma URL autorizada.'
    match = re.fullmatch(r'(verificar|resumir|exportar|revisar) caso ([0-9a-f]{32})', text)
    if not match: return None
    action, ident = match.groups(); case = locate(ident)
    if action=='resumir':return case.text_summary()
    if action in ('verificar','resumir'):
        result = case.verify()
        return f"Caso {ident}\nIntegridade verificada: {result['artifacts']} artefatos e {result['events']} eventos de custódia.\nChave pública SHA256: {result['signer_sha256']}\nHorário do aparelho; identidade humana e autenticidade da origem não certificadas."
    directory = private_dir(ROOT/'forensic-exports'); name = ident+'-'+str(time.time_ns())
    if action == 'exportar':
        path=directory/(name+'.zip'); result=case.export(path)
        return f"Pacote criptografado exportado: {path}\nSHA256: {result['package_sha256']}\nChave pública SHA256: {result['signer_sha256']}\nA chave de descriptografia não acompanha o pacote."
    result=case.review(directory/(name+'.html'))
    return f"Revisão offline gerada: {result['path']}\nHTML sem execução de scripts nem conexões externas. Prévia com redação automática; revise antes de compartilhar."


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='command',required=True)
    for command in ('verify','timeline','export','review','import-log','add-analysis','extract','redact'):
        p=sub.add_parser(command);p.add_argument('case');p.add_argument('--actor');p.add_argument('--key-dir');p.add_argument('--anchors')
        if command in ('export','review'):p.add_argument('output')
        if command in ('import-log','add-analysis'):p.add_argument('input')
        if command=='import-log':p.add_argument('--source',required=True)
        if command in ('extract','redact'):p.add_argument('artifact_id');p.add_argument('value')
    p=sub.add_parser('backup-keys');p.add_argument('output');p.add_argument('--password-file',required=True);p.add_argument('--key-dir',default=str(ROOT/'forensic-keys'))
    p=sub.add_parser('restore-keys');p.add_argument('backup');p.add_argument('directory');p.add_argument('--password-file',required=True)
    p=sub.add_parser('restore-package');p.add_argument('package');p.add_argument('destination');p.add_argument('--key-dir',required=True);p.add_argument('--anchors',required=True);p.add_argument('--trusted-key',required=True)
    args=parser.parse_args()
    if args.command=='restore-package':result=restore_package(args.package,args.destination,args.key_dir,args.anchors,args.trusted_key)
    elif args.command in ('backup-keys','restore-keys'):
        password_path=Path(args.password_file)
        if password_path.stat().st_mode&0o077:raise ValueError('Password file requires 0600')
        password=read_regular(password_path,4096).strip()
        if args.command=='backup-keys':Keys(args.key_dir).backup(args.output,password);result={'created':args.output}
        else:result={'signer_sha256':Keys.restore(args.backup,args.directory,password).fingerprint}
    else:
        case=Case(args.case,args.key_dir,args.anchors,actor=args.actor)
        if args.command=='verify':result=case.verify()
        elif args.command=='timeline':case.event('timeline_review');result=case.timeline()
        elif args.command=='export':result=case.export(args.output)
        elif args.command=='review':result=case.review(args.output)
        elif args.command=='import-log':result={'artifact_id':case.import_log(args.input,args.source)}
        elif args.command=='extract':result=case.extract(args.artifact_id,args.value)
        elif args.command=='redact':
            profile=Path(args.value)
            if profile.stat().st_mode&0o077:raise ValueError('Redaction file requires 0600')
            result={'artifact_id':case.derive_redaction(args.artifact_id,json.loads(read_regular(profile,65536)))}
        else:result={'artifact_id':case.add_analysis(json.loads(read_regular(args.input)))}
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
