SKILLS = {
    'recon': {
        'actions': ['inspect_http', 'http_request', 'crawl'],
        'purpose': 'Mapear resposta, tecnologia, cabeçalhos, rotas e formulários antes de propor testes.'
    },
    'sqli': {
        'actions': ['probe_http', 'sqlmap', 'http_request'],
        'purpose': 'Investigar parâmetros dinâmico, separar indícios de SQLi confirmada e não extrair dados.'
    },
    'xss': {
        'actions': ['xss_probe', 'http_request'],
        'purpose': 'Verificar reflexão e injeção de marcação; XSS explorável exige confirmação de contexto.'
    },
    'services': {
        'actions': ['nmap'],
        'purpose': 'Identificar serviços expostos e versões somente quando essa descoberta for necessária.'
    },
    'exposure': {
        'actions': ['nuclei'],
        'purpose': 'Selecionar tecnologias, exposições, configurações ou CVEs compatíveis com as evidências.'
    },
    'custom_http': {
        'actions': ['http_request'],
        'purpose': 'Testar uma hipótese com método, rota e corpo escolhidos pelo agente dentro da origem autorizada.'
    },
    'methodology': {
        'actions': ['skill_cli'],
        'purpose': 'Manter memória SQLite, sitemap e hipóteses OWASP; criar testes próprios e consultar cobertura entre execuções.',
        'source': 'https://github.com/strobes-security/web-pentest-sample',
        'commit': '101c3fd96e2ffda27886973dea7089b93bc79756',
        'archive_sha256': '6032e661c8f4e89b9156daba6b56f8cb60ed6ee8638a74a6a801cd66495b2d3a'
    }
}


def prompt():
    return '\n'.join('- '+name+': '+skill['purpose']+' Ações: '+', '.join(skill['actions'])+'.'
                     for name, skill in SKILLS.items())
