"""Passive, evidence-based checks. No payloads, form submission or security score."""
import html.parser
import re
import urllib.parse as U

# Severity is a review priority, never proof of exploitation.
RULES = {
 'csp_absent': ('CSP ausente no cabeçalho HTML', 'low', 'Definir uma CSP adequada ao site; verificar também políticas em meta.', 'Sem política no cabeçalho; isso sozinho não confirma XSS.'),
 'csp_script_unrestricted': ('CSP sem restrição efetiva de origem de scripts', 'medium', 'Restringir script-src/default-src a origens necessárias e avaliar nonces ou hashes.', 'A política observada permite origens amplas ou não define uma lista de scripts.'),
 'csp_unsafe_eval': ('CSP permite avaliação dinâmica de código', 'low', 'Revisar dependências e remover unsafe-eval quando possível.', 'A permissão amplia a superfície; não comprova injeção.'),
 'csp_inline_allowed': ('CSP permite scripts inline sem nonce ou hash', 'low', 'Migrar scripts inline para nonces, hashes ou arquivos autorizados.', 'Depende do contexto e das demais defesas contra injeção.'),
 'hsts_absent': ('HSTS ausente na resposta HTTPS', 'low', 'Avaliar Strict-Transport-Security após garantir HTTPS nas rotas necessárias.', 'Não foi avaliada a lista de preload do navegador.'),
 'hsts_invalid': ('HSTS sem max-age positivo válido', 'medium', 'Configurar max-age positivo após validar a implantação HTTPS.', 'A diretiva observada não ativa retenção HSTS nesta resposta.'),
 'nosniff_missing': ('X-Content-Type-Options sem nosniff', 'low', 'Enviar X-Content-Type-Options: nosniff e MIME correto.', 'Observação de configuração; impacto depende do conteúdo.'),
 'frame_guard_missing': ('Restrição de enquadramento não observada nos cabeçalhos', 'low', 'Avaliar CSP frame-ancestors ou X-Frame-Options conforme o uso do site.', 'Páginas públicas incorporáveis podem permitir enquadramento intencionalmente.'),
 'referrer_unsafe': ('Referrer-Policy permite envio amplo da URL', 'low', 'Avaliar strict-origin-when-cross-origin ou política mais restritiva.', 'Não foram procurados dados pessoais em URLs.'),
 'cookie_without_secure': ('Cookie HTTPS sem Secure', 'medium', 'Aplicar Secure aos cookies que precisam de transporte HTTPS.', 'Não determina se o cookie contém autenticação.'),
 'cookie_without_httponly': ('Cookie sem HttpOnly', 'low', 'Aplicar HttpOnly aos cookies de sessão que não precisam ser lidos por JavaScript.', 'Cookies usados pelo frontend podem exigir acesso legítimo por JavaScript.'),
 'cookie_samesite_unspecified': ('Cookie sem SameSite válido explícito', 'low', 'Definir SameSite conforme o fluxo de autenticação e navegação.', 'Navegadores podem aplicar Lax por padrão; isso não confirma CSRF.'),
 'cookie_none_without_secure': ('SameSite=None sem Secure', 'medium', 'Combinar SameSite=None com Secure quando o acesso entre sites for necessário.', 'Navegadores modernos podem rejeitar esse cookie.'),
 'http_unencrypted': ('Resposta recebida por HTTP sem TLS', 'low', 'Usar HTTPS em produção; distinguir serviços locais de páginas públicas.', 'Observação da URL consultada; não testa todas as alternativas HTTPS.'),
 'mixed_content': ('Referência HTTP em recurso de uma página HTTPS', 'medium', 'Trocar recursos HTTP por HTTPS e verificar o comportamento no navegador.', 'O navegador pode bloquear ou atualizar o recurso; carregamento inseguro não foi comprovado.'),
 'password_form_http': ('Formulário de senha em transporte HTTP', 'high', 'Servir a página e a ação do formulário por HTTPS.', 'Prioridade alta para revisão; nenhuma senha foi enviada.'),
 'password_form_get': ('Formulário de senha usa método GET', 'medium', 'Usar POST por HTTPS e evitar senhas na URL.', 'A análise é do HTML; JavaScript pode alterar o envio. Nenhum formulário foi enviado.'),
 'error_detail_marker': ('Detalhes de erro técnico na resposta 5xx', 'medium', 'Remover stack traces da resposta pública e manter detalhes nos logs internos.', 'Marcador conhecido observado; valores do corpo não são publicados.'),
}
SIGNALS = {key: value[0] for key, value in RULES.items()}

class Markup(html.parser.HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url = url; self.base = url; self.form = None; self.forms = []; self.mixed = 0
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'base' and a.get('href'): self.base = U.urljoin(self.url, a['href'])
        if tag in ('script','img','iframe','audio','video','source','link','object'):
            for key in ('src','href' if tag == 'link' else 'data' if tag == 'object' else 'src'):
                if a.get(key) and self.url.startswith('https:') and U.urljoin(self.base,a[key]).startswith('http:'):
                    self.mixed += 1; break
        if tag == 'form':
            self.form = {'action':U.urljoin(self.base,a.get('action') or self.url),'method':a.get('method','get').lower(),'password':False}
            self.forms.append(self.form)
        if tag == 'input' and a.get('type','').lower() == 'password' and self.form is not None:
            self.form['password'] = True
    def handle_endtag(self, tag):
        if tag == 'form': self.form = None


def policies(value):
    result=[]
    for policy in value.split(','):
        directives={}
        for raw in policy.split(';'):
            words=raw.strip().split()
            if words:directives.setdefault(words[0].lower(),[x.lower() for x in words[1:]])
        result.append(directives)
    return result


def inspect(response):
    h=response['headers'];body=response['body'];url=response['url']
    html='html' in h.get('content-type','').lower();https=url.startswith('https:');signals=[]
    if not https:signals.append('http_unencrypted')
    if https:
        hsts=h.get('strict-transport-security','')
        if not hsts:signals.append('hsts_absent')
        else:
            ages=re.findall(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)',hsts,re.I)
            if len(ages)!=1 or not any(c!='0' for c in ages[0]):signals.append('hsts_invalid')
    if html:
        csp=h.get('content-security-policy','');ps=policies(csp) if csp else []
        if not csp:signals.append('csp_absent')
        elif ps:
            scripts=[p.get('script-src-elem',p.get('script-src',p.get('default-src'))) for p in ps]
            def broad(s):return s is None or any(x in s for x in ('*','http:','https:','data:'))
            if all(broad(s) for s in scripts):signals.append('csp_script_unrestricted')
            if all(s is None or "'unsafe-inline'" in s and not any(x.startswith(("'nonce-","'sha256-","'sha384-","'sha512-")) for x in s) for s in scripts):signals.append('csp_inline_allowed')
            evals=[p.get('script-src',p.get('default-src')) for p in ps]
            if all(s is None or "'unsafe-eval'" in s for s in evals):signals.append('csp_unsafe_eval')
        frame=any('frame-ancestors' in p and '*' not in p['frame-ancestors'] for p in ps)
        if not frame and h.get('x-frame-options','').strip().lower() not in ('deny','sameorigin'):signals.append('frame_guard_missing')
        if h.get('x-content-type-options','').strip().lower()!='nosniff':signals.append('nosniff_missing')
        ref=[v.strip().lower() for v in h.get('referrer-policy','').split(',')]
        valid={'no-referrer','no-referrer-when-downgrade','same-origin','origin','strict-origin','origin-when-cross-origin','strict-origin-when-cross-origin','unsafe-url'}
        effective=next((v for v in reversed(ref) if v in valid),None)
        if effective in ('unsafe-url','no-referrer-when-downgrade'):signals.append('referrer_unsafe')
        parser=Markup(url)
        try:parser.feed(body.decode('utf-8','replace'))
        except (ValueError,RecursionError):pass
        if parser.mixed:signals.append('mixed_content')
        password=[f for f in parser.forms if f['password']]
        if any(not https or f['action'].startswith('http:') for f in password):signals.append('password_form_http')
        if any(f['method']=='get' for f in password):signals.append('password_form_get')
    cookies=response.get('cookie_flags',[])
    if https and any(not c.get('secure') for c in cookies):signals.append('cookie_without_secure')
    if any(not c.get('httponly') for c in cookies):signals.append('cookie_without_httponly')
    if any(not c.get('samesite') for c in cookies):signals.append('cookie_samesite_unspecified')
    if any(c.get('samesite_value')=='none' and not c.get('secure') for c in cookies):signals.append('cookie_none_without_secure')
    if response['status']>=500 and any(s in body for s in (b'Traceback (most recent call last)',b'java.lang.',b'Stack trace:')):signals.append('error_detail_marker')
    return list(dict.fromkeys(signals))


def public_step(report):
    """Bounded mobile snapshot; complete observations remain in the saved report."""
    order={'high':0,'medium':1,'low':2}
    findings=sorted(report['hypotheses'],key=lambda h:order.get(h.get('severity'),3))
    sample=findings[:60]
    pages=report['pages'][:100]
    return {'tool':'qa_map','job_id':report['job_id'],'coverage':report['coverage'],'javascript_executed':report['javascript_executed'],
            'requests':report['requests'],'javascript_pages':report['javascript_pages'],'browser_errors':report['browser_errors'],
            'queue_exhausted':report['completion']['queue_exhausted'],'inventory_complete':report['completion']['discovered_inventory_analyzed'],
            'hypotheses':sample,'pages':[{k:p.get(k) for k in ('url','state','status','error','truncated')} for p in pages],
            'findings_total':len(findings),'findings_omitted':len(findings)-len(sample),'pages_total':len(report['pages']),
            'pages_omitted':len(report['pages'])-len(pages),'checks_catalog':len(RULES),
            'learning':report.get('learning',{}),'assessment':'Revisão passiva; segurança global não comprovada',
            'not_tested':'Controle de acesso entre usuários, lógica de negócio, SQLi, XSS executável e envio de formulários não foram testados por este mapeamento.'}


def save_public_report(root, report):
    """Only public findings and inventory; excludes raw bodies, secrets and model output."""
    import json
    import os
    from pathlib import Path
    result=public_step(report)
    result['hypotheses']=report['hypotheses']
    result['pages']=[{k:p.get(k) for k in ('url','state','status','error','truncated')} for p in report['pages']]
    result.update(findings_omitted=0,pages_omitted=0,scope=report['scope'],status=report['status'],stop_reason=report.get('stop_reason'),limitations=report['limitations'])
    folder=Path(root)/'reports';folder.mkdir(exist_ok=True)
    if not re.fullmatch(r'[a-f0-9]{32}',report['job_id']):raise ValueError('ID de relatório inválido')
    dest=folder/(report['job_id']+'-security.json');tmp=dest.with_suffix('.tmp')
    with tmp.open('w') as out:
        os.chmod(tmp,0o600);json.dump(result,out,ensure_ascii=False,indent=2)
    tmp.replace(dest)
    return dest
