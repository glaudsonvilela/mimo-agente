"""Instala a dependência pública de metodologia, fixada por commit e SHA256."""
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

COMMIT = '101c3fd96e2ffda27886973dea7089b93bc79756'
SHA256 = 'b324c48319df5541f92eb4acd1d27b72ff43ab1fa63a93f33bbe1373d2358fd4'
URL = f'https://codeload.github.com/strobes-security/web-pentest-sample/tar.gz/{COMMIT}'
target = Path(__file__).resolve().parents[1] / 'backend/skills/web-pentest'
if target.exists():
    raise SystemExit('Destino já existe; remova-o manualmente se quiser reinstalar.')
with urllib.request.urlopen(URL, timeout=60) as response:
    payload = response.read(20 * 1024 * 1024 + 1)
if hashlib.sha256(payload).hexdigest() != SHA256:
    raise SystemExit('SHA256 inesperado; nada foi instalado.')
with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
    entries = []
    for member in archive.getmembers():
        parts = Path(member.name).parts[1:]
        if not parts:
            continue
        if any(part in ('..', '/') for part in parts) or not (member.isfile() or member.isdir()):
            raise SystemExit('Arquivo contém entrada não permitida.')
        entries.append((member, target.joinpath(*parts)))
    target.mkdir(parents=True)
    for member, path in entries:
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
print('Metodologia instalada com verificação SHA256; licença upstream preservada.')
