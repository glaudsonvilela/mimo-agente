"""Per-origin memory of measured facts; never stores page instructions or trains weights."""
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.parse as U
import qa_security

LIMIT=5000

def location(root,scope):
    p=U.urlsplit(scope)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:raise ValueError('Origem inválida')
    key=(p.scheme,p.hostname.lower(),p.port or (443 if p.scheme=='https' else 80))
    return Path(root)/'projects'/hashlib.sha256(repr(key).encode()).hexdigest()[:20]/'learning.json'

def read(root,scope):
    path=location(root,scope)
    if not path.exists():return {'version':1,'runs':0,'routes':[],'observations':{},'last_job':None,'last_javascript_pages':0}
    if path.stat().st_size>2_000_000:raise ValueError('Memória excedeu limite')
    memory=json.loads(path.read_text())
    if memory.get('version')!=1 or not isinstance(memory.get('runs'),int) or not isinstance(memory.get('routes'),list) or not isinstance(memory.get('observations'),dict):raise ValueError('Memória inválida')
    return memory

def context(root,scope):
    memory=read(root,scope)
    return {'previous_runs':memory['runs'],'known_routes':len(memory['routes']),
            'previous_reproduced_observations':len(memory['observations']),
            'previous_javascript_pages':memory.get('last_javascript_pages',0)}

def record(root,report):
    memory=read(root,report['scope'])
    if report['status']!='finished' or report['coverage']['pending']:
        return {'saved':False,'previous_runs':memory['runs'],'message':'A análise ficou incompleta. Vou guardar novos aprendizados quando ela terminar.'}
    if memory['last_job']==report['job_id']:
        return dict(memory.get('last_summary',{}),saved=True)
    def route_id(url):
        # No credential values, query parameters, titles or page prose are persisted.
        p=U.urlsplit(url);return hashlib.sha256((p.scheme+'://'+p.netloc+p.path).encode()).hexdigest()
    visited={route_id(p['url']) for p in report['pages'] if p['state']=='analyzed' and not p.get('truncated')}
    prior=set(memory['routes']);observations={}
    for h in report['hypotheses']:
        if h['status']=='confirmed_observation' and h['signal'] in qa_security.SIGNALS:
            key=route_id(h['url'])+':'+h['signal'];observations[key]={'signal':h['signal'],'case_id':report['job_id']}
    recurring=len(set(observations)&set(memory['observations']))
    summary={'saved':True,'previous_runs':memory['runs'],'runs':memory['runs']+1,'new_routes':len(visited-prior),
             'reproduced_observations':len(observations),'recurring_observations':recurring,
             'memory_limited':len(prior|visited)>LIMIT or len(observations)>LIMIT}
    if memory['runs']:
        summary['message']=f"Comparei com a visita anterior: {summary['new_routes']} caminhos novos e {recurring} indícios que reapareceram. Guardei o resultado."
    else:
        summary['message']=f"Guardei {len(visited)} caminhos e {len(observations)} observações reproduzidas para comparar na próxima visita."
    memory.update(runs=summary['runs'],routes=sorted(prior|visited)[:LIMIT],observations=dict(list(observations.items())[:LIMIT]),
                  last_job=report['job_id'],last_javascript_pages=report['javascript_pages'],last_summary=summary,updated_at=time.time())
    path=location(root,report['scope']);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp')
    with tmp.open('w') as stream:os.chmod(tmp,0o600);json.dump(memory,stream,ensure_ascii=False)
    tmp.replace(path);return summary
