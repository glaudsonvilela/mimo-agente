"""Gera configuração local sem copiar credenciais de outra instalação."""
import os
from pathlib import Path
import secrets
import shutil

root = Path(__file__).resolve().parents[1] / 'backend'
token = root / 'token'
try:
    fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print('Credencial local já existe; preservada.')
else:
    with os.fdopen(fd, 'w') as stream:
        stream.write(secrets.token_hex(32) + '\n')
    print('Credencial local criada (valor não exibido).')
settings = root / 'qa-settings.json'
if not settings.exists():
    shutil.copyfile(root / 'qa-settings.example.json', settings)
    settings.chmod(0o600)
print('Configuração local pronta. Não publique o token nem APKs que o contenham.')
