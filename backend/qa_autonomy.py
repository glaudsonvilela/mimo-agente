"""Validated traversal policy; model choices cannot expand scope or execute commands."""
import hashlib
from pathlib import Path

DEFAULTS = {'mode': 'exhaustive', 'max_urls': 5000, 'max_requests': 15000, 'max_seconds': 3600}
STRATEGIES = ('breadth_first', 'parameters_first', 'scripts_first', 'pause')
REASONS = {
    'coverage': 'Continuar pelos endereços ainda não analisados.',
    'parameters': 'Priorizar rotas com parâmetros observados.',
    'javascript': 'Priorizar scripts para descobrir rotas dinâmicas.',
    'review': 'Pausar para revisar uma limitação identificada.',
}
SCHEMA = {'type': 'object', 'properties': {
    'strategy': {'type': 'string', 'enum': list(STRATEGIES)},
    'reason': {'type': 'string', 'enum': list(REASONS)},
}, 'required': ['strategy', 'reason'], 'additionalProperties': False}


def settings(value):
    if not value:
        return None
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('Configuração de autonomia inválida')
    result = dict(DEFAULTS, **value)
    if result['mode'] != 'exhaustive':
        raise ValueError('Modo de navegação inválido')
    for key, maximum in (('max_urls', 20000), ('max_requests', 60000), ('max_seconds', 14400)):
        if type(result[key]) is not int or not 1 <= result[key] <= maximum:
            raise ValueError('Limite de autonomia inválido: ' + key)
    return result


def validate(plan):
    if not isinstance(plan, dict) or set(plan) != {'strategy', 'reason'}:
        raise ValueError('Decisão autônoma inválida')
    if plan['strategy'] not in STRATEGIES or plan['reason'] not in REASONS:
        raise ValueError('Decisão autônoma fora do catálogo')
    return dict(plan)


def methodology(root):
    path = Path(root) / 'skills/web-pentest/SKILL.md'
    raw = path.read_bytes()
    if len(raw) > 256000:
        raise ValueError('Skill excede o limite de leitura')
    text = raw.decode('utf-8')
    # Use installed methodology, excluding exploit playbooks and payload examples.
    parts = []
    for heading, end in (('### Phase 1:', '### Phase 2:'),
                         ('### Phase 3:', '### Phase 4:'),
                         ('### Phase 6:', '## Script Reference'),
                         ('## Rules & Constraints', None)):
        if heading not in text:
            raise ValueError('Skill instalada sem seção esperada: ' + heading)
        block = text.split(heading, 1)[1]
        if end:
            block = block.split(end, 1)[0]
        in_code = False
        prose = []
        for line in block.splitlines():
            if line.strip().startswith('```'):
                in_code = not in_code
            elif not in_code and line.strip():
                prose.append(line)
        parts.append(heading + '\n' + '\n'.join(prose))
    return {'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'guidance': '\n'.join(parts)[:4200]}


def full_inventory_requested(normalized):
    """Scoped analysis defaults to the persistent inventory, never the 3-page reader."""
    import re
    explicit_tool = re.search(r'\b(sqlmap|nuclei|nmap|sqli|xss|skill_cli)\b', normalized)
    broad = re.search(r'\b(todos|todas|completo|completa|forense|mapear|mapeie|mapeamento|crawler|autonomo|autonoma)\b', normalized)
    one_page = re.search(r'(apenas|somente|so) (esta|essa|a|uma) pagina', normalized)
    return bool(broad or not (explicit_tool or one_page))
