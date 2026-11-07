"""Origin-bound, memory-only credentials supplied by the operator."""
import http.cookies
import json
import os
from pathlib import Path
import time
import urllib.parse as U


class SessionExpired(Exception):
    pass


class Session:
    def __init__(self, scope, headers=None, expires_at=None, lab=False):
        self.origin = self.key(scope)
        self.headers = {}; self.cookies = {}; self.secrets = set()
        self.expires_at = float(expires_at) if expires_at else None
        self.state = 'anonymous'; self.events = []
        if headers and self.origin[0] != 'https' and not lab:
            raise ValueError('Sessão exige HTTPS; HTTP somente no laboratório loopback')
        for name, value in (headers or {}).items():
            if not isinstance(value, str) or len(value)>8192 or '\r' in value or '\n' in value:
                raise ValueError('Cabeçalho de sessão inválido')
            if name.lower() not in ('authorization','cookie','accept-language'):
                raise ValueError('Cabeçalho não permitido')
            if name.lower()=='cookie':
                jar=http.cookies.SimpleCookie();jar.load(value)
                for key,item in jar.items():self.cookies[key]=item.value;self.secrets.add(item.value)
            else:self.headers[name.title()]=value
            if name.lower() in ('authorization','cookie'):
                self.secrets.add(value);self.secrets.add(value.removeprefix('Bearer '));self.state='provided'

    @staticmethod
    def key(url):
        p=U.urlsplit(url)
        return p.scheme,p.hostname,p.port or (443 if p.scheme=='https' else 80)

    @classmethod
    def load(cls, path, scope, lab=False):
        path=Path(path)
        stat=path.stat()
        if stat.st_mode&0o077 or stat.st_uid!=os.geteuid() or path.is_symlink() or stat.st_size>16384:
            raise ValueError('Arquivo de sessão deve pertencer ao usuário, sem symlink, até 16 KiB e permissão 0600')
        data=json.loads(path.read_text())
        if cls.key(data.get('origin',''))!=cls.key(scope):raise ValueError('Sessão pertence a outra origem')
        return cls(scope,data.get('headers',{}),data.get('expires_at'),lab)

    def outgoing(self, url):
        if self.key(url)!=self.origin:raise ValueError('Credenciais bloqueadas fora da origem')
        if self.state=='expired' or self.expires_at and time.time()>=self.expires_at:
            self.expire('Prazo da sessão informado pelo usuário');raise SessionExpired('Sessão expirada; forneça uma sessão atualizada e retome')
        headers=dict(self.headers)
        if self.cookies:headers['Cookie']='; '.join(k+'='+v for k,v in self.cookies.items())
        return headers

    def expire(self, reason):
        self.state='expired';self.headers.clear();self.cookies.clear()
        self.events.append({'state':'expired','reason':reason})

    def accept(self, response):
        if self.key(response['url'])!=self.origin:raise ValueError('Resposta fora da origem da sessão')
        was_authenticated=self.state in ('provided','active')
        for raw in response.pop('set_cookies',[]):
            jar=http.cookies.SimpleCookie();jar.load(raw)
            for name,item in jar.items():
                self.secrets.add(item.value)
                # Only host cookies scoped to / are reused. Domain/path cases require an operator session refresh.
                if item['domain'] or item['path'] not in ('','/'):
                    self.events.append({'state':'cookie_not_reused','reason':'Cookie Domain/Path exige sessão fornecida pelo usuário'});continue
                if item['max-age']=='0' or not item.value:self.cookies.pop(name,None)
                else:self.cookies[name]=item.value
        location=response['headers'].get('location','')
        path=U.urlsplit(U.urljoin(response['url'],location)).path.lower()
        if was_authenticated and (response['status'] in (401,403) or 300<=response['status']<400 and any(x in path.split('/') for x in ('login','signin','logout'))):
            self.expire('Servidor recusou a sessão ou redirecionou para autenticação')
            raise SessionExpired('Sessão recusada/expirada; envio de credenciais suspenso. Atualize a sessão e retome')
        if was_authenticated:self.state='active'

    def public(self):return {'state':self.state,'credential_values_logged':False,'events':self.events[-10:]}
