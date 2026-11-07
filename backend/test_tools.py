import json,threading
from pathlib import Path
import tools
root=Path('reports/smoke');root.mkdir(parents=True,exist_ok=True)
url='http://127.0.0.1:8099/'
print(json.dumps({'nmap':tools.execute('nmap',url,url)},ensure_ascii=False),flush=True)
template=root/'fixture.yaml';template.write_text('''id: poco-local-fixture
info:
  name: POCO controlled local fixture
  author: local
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "X-Poco-Fixture: controlled-local-lab"
        case-insensitive: true
''')
with tools.ScopeProxy(('127.0.0.1',0),tools.ProxyHandler) as proxy:
 proxy.allowed=tools.origin(tools.url_parts(url));threading.Thread(target=proxy.serve_forever,daemon=True).start()
 endpoint='http://127.0.0.1:'+str(proxy.server_address[1]);output=root/'nuclei.jsonl'
 result=tools.run_process([str(tools.location('nuclei')/'nuclei'),'-u',url,'-t',str(template),'-ni','-duc','-dr','-rl','2','-c','1','-bs','1','-proxy',endpoint,'-pi','-jsonl','-omit-raw','-o',str(output),'-nc'],root,timeout=60)
 result['findings']=[json.loads(s) for s in output.read_text().splitlines()] if output.exists() else []
 proxy.shutdown()
 assert any(f.get('template-id')=='poco-local-fixture' for f in result['findings']),result
 print(json.dumps({'nuclei':result},ensure_ascii=False),flush=True)
