"""Reproducible read-only observations, known-inventory comparison and bounded verification."""
import hashlib
import json
import time
import urllib.parse as U
import qa_security


def response_evidence(response, clean, request_id, context=None):
    headers=response['headers'];body=response['body'];ctype=headers.get('content-type','')
    security={name:bool(headers.get(name)) for name in ('content-security-policy','strict-transport-security','x-content-type-options','referrer-policy')}
    signals=qa_security.inspect(response)
    cookies=response.get('cookie_flags',[])
    return {'id':request_id,'observed_at':time.time(),'request':{'method':'GET','url':clean(response['url']),'credential_values':'omitted'},
            'response':{'status':response['status'],'content_type':clean(ctype),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'truncated':response['truncated'],'peer':response['peer'],'tls':response.get('tls'),
                        'security_headers_present':security,'cookie_flags':cookies},
            'signals':signals,'context':context or {'step':'http_navigation'},
            'reproduce':{'method':'GET','url':clean(response['url']),'same_origin_only':True,'session':'Supply a fresh operator session if required; never copy credentials from logs'}}


def known_coverage(report, manifest):
    if not manifest:return {'basis':'discovered_inventory_only','total_site_coverage':None,'reason':'Sem inventário esperado fornecido pelo operador'}
    expected=manifest.get('routes',[])
    if not isinstance(expected,list) or len(expected)>1000 or not all(isinstance(x,str) and x.startswith('/') and not x.startswith('//') for x in expected):raise ValueError('Manifesto de cobertura inválido')
    def route(url):
        p=U.urlsplit(url);return U.urlunsplit(('', '', p.path or '/',p.query,''))
    rows={route(p['url']):p for p in report['pages'] if U.urlsplit(p['url']).netloc==U.urlsplit(report['scope']).netloc}
    items=[]
    for path in sorted(set(expected)):
        row=rows.get(path)
        state='not_discovered' if row is None else row['state']
        items.append({'route':path,'status':state,'visited':bool(row and row['visited']),'reason':row.get('error') if row else 'Não encontrada pelos caminhos executados'})
    actions={x['data'].get('id') for x in report['inventory'] if x['kind']=='navigation_action' and x['data'].get('status')=='completed'}
    forms={route(x['data']['action']) for x in report['inventory'] if x['kind']=='form' and x['data']['action'].startswith(('http://','https://'))}
    endpoints={route(x['data']['url']) for x in report['inventory'] if x['kind']=='browser_request'}
    states={route(x['data']['url']) for x in report['inventory'] if x['kind']=='navigation_state'}
    groups={}
    for name,found in (('actions',actions),('forms',forms),('endpoints',endpoints),('states',states)):
        wanted=set(manifest.get(name,[]));groups[name]={'expected':len(wanted),'observed':sorted(wanted&found),'missing':sorted(wanted-found)}
    visited=sum(i['visited'] for i in items);analyzed=sum(i['status']=='analyzed' for i in items)
    return {'basis':'operator_manifest','manifest_name':str(manifest.get('name',''))[:120],'expected_routes':len(items),'discovered_routes':sum(i['status']!='not_discovered' for i in items),
            'visited_routes':visited,'analyzed_routes':analyzed,'analyzed_percent':round(100*analyzed/len(items),1) if items else None,'routes':items,'groups':groups,
            'limitation':'Percentual somente do manifesto fornecido; não prova ausência de rotas desconhecidas'}


SIGNALS=qa_security.SIGNALS


def hypotheses(evidence, checks):
    result=[];seen=set()
    indexed={(x['url'],x['signal']):x for x in checks}
    for item in evidence:
        for signal in item.get('signals',[]):
            key=(item['request']['url'],signal)
            if key in seen:continue
            seen.add(key)
            match=indexed.get(key)
            result.append({'hypothesis':SIGNALS[signal],'url':key[0],'signal':signal,'evidence_ids':[item['id']]+(match.get('evidence_ids',[]) if match else []),
                           'status':match['status'] if match else 'not_tested','verification':match.get('reason') if match else 'Observação inicial; sem repetição independente',
                           'impact':qa_security.RULES[signal][3], 'severity':qa_security.RULES[signal][1],
                           'recommendation':qa_security.RULES[signal][2],
                           'evidence': 'HTTP '+str(item['response']['status'])+'; evidência '+str(item['id'])+'; SHA256 '+item['response']['sha256']+('; corpo truncado' if item['response']['truncated'] else ''),
                           'reproduce':item['reproduce']})
    return result
