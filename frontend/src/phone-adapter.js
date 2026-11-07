/** Maps the existing POCO /api/state contract to public UI events.
 * This file makes no network requests and does not read reasoning or planning output.
 * The native Android frontend must supply authenticated snapshots through the native bridge.
 */
export function stateToPublicEvents(snapshot, previous = null) {
  if (!snapshot || typeof snapshot !== 'object') return [];
  const events=[];
  const descriptions={qa_map:'Mapeamento persistente: acompanha URLs, evidências e pendências.',qa_plan:'O modelo local consulta a skill para escolher a próxima prioridade.',crawl:'O coletor está lendo páginas e reunindo fontes.',inspect_http:'A ferramenta está observando a resposta HTTP, tecnologias e cabeçalhos.',probe_http:'A ferramenta está comparando respostas de parâmetros.',xss_probe:'A ferramenta está verificando reflexão de um marcador inerte.',http_request:'A ferramenta está consultando uma rota dentro do escopo.',skill_cli:'O agente está consultando a metodologia e a memória do projeto.',nuclei:'A ferramenta está executando verificações selecionadas do catálogo.',sqlmap:'A ferramenta está investigando parâmetros e reunindo evidências.',nmap:'A ferramenta está identificando serviços no escopo definido.'};
  const phase=typeof snapshot.phase==='string'?snapshot.phase.slice(0,300):'';
  const decision=typeof snapshot.decision==='string'?snapshot.decision:'';
  if(phase&&(!previous||phase!==previous.phase||decision!==previous.decision||snapshot.active!==previous.active))events.push({id:'phase-'+String(snapshot.updated_at||Date.now()),type:phase==='Erro'||phase==='Interrompido'?'error':snapshot.active===false&&phase==='Concluído'?'complete':descriptions[decision]?'tool':'action',title:phase,summary:descriptions[decision]||'Atualização pública de estado recebida do agente.',tool:descriptions[decision]?decision:undefined});
  const steps=Array.isArray(snapshot.evidence?.steps)?snapshot.evidence.steps:[];
  for(let i=0;i<Math.min(steps.length,100);i++) { const step=steps[i];if(!step||typeof step!=='object')continue;const output={};for(const key of ['tool','url','status','returncode','timed_out','execution_complete','confirmation_status','markup_injected','content_type'])if(['string','number','boolean'].includes(typeof step[key]))output[key]=typeof step[key]==='string'?step[key].slice(0,2000):step[key];events.push({id:'evidence-'+i,type:'tool',title:'Evidência recebida',summary:'Resultado publicado pelo agente. A ausência de um achado não comprova ausência de vulnerabilidades.',tool:typeof step.tool==='string'?step.tool.slice(0,100):'ferramenta',output}); }
  return events;
}
