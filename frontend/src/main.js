import { createLiveSession } from './live-session.js';
import { saveFile } from './download.js';
import { createMascot } from './mascot.js';
import { createDocumentation } from './documentation.js';
import { stateToPublicEvents } from './phone-adapter.js';
const nativeMode=Boolean(window.PocoNative?.sendMessage);
let live=null, connected=!nativeMode;
const $ = selector => document.querySelector(selector);
const state={view:'chat',filter:'all',mood:'idle',events:[],messages:[],timers:[],clock:0,started:0,active:false,unread:false,sequence:0};
const mascot=createMascot($('#mascot'),()=>state.mood);
const $node=(tag,cls,text)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;};
const icon=name=>{const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'),use=document.createElementNS('http://www.w3.org/2000/svg','use');use.setAttribute('href','#i-'+name);svg.append(use);svg.setAttribute('aria-hidden','true');return svg;};
function toast(text){$('#toast').textContent=text;$('#toast').hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').hidden=true,4000);}
const documentation=createDocumentation($('#documentation'),nativeMode?null:()=>{startDemo('Leia este link e documente o que encontrou.','https://example.com');view('docs');},toast);
function scrollToPanel(){if(innerWidth<761)window.scrollTo({top:0,behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});}
function view(name){state.view=name;document.querySelectorAll('.view').forEach(el=>el.classList.toggle('active',el.id==='view-'+name));document.querySelectorAll('[data-view]').forEach(button=>{button.classList.toggle('selected',button.dataset.view===name);if(button.dataset.view===name)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});$('#composer').hidden=name!=='chat';if(name==='activity'){$('#event-dot').hidden=true;state.unread=false;}scrollToPanel();}
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>view(button.dataset.view)));
function mood(type,phase){state.mood=type;const label=type==='done'?'MISSÃO NAS PEQUENAS GARRAS':type==='tool'?'FERRAMENTAS À MÃO':type==='error'?'UM PEQUENO IMPREVISTO':type==='idle'?'ACORDADO E CURIOSO':'CONCENTRADO. QUASE PERIGOSO.';$('#creature-state').replaceChildren($node('i'),document.createTextNode(label));if(phase){$('#task-phase').textContent=phase;$('#activity-state').replaceChildren($node('i'),document.createTextNode(phase));}}
function formatTime(seconds){return String(Math.floor(seconds/60)).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0');}
function publicData(value){if(value===undefined)return '';try{return (typeof value==='string'?value:JSON.stringify(value,(key,val)=>/^(reasoning|reasoning_content|chain_of_thought|thinking|analysis|scratchpad|authorization|password|secret|api[_-]?key|token)$/i.test(key)?undefined:val,2)).slice(0,16000);}catch{return '[dados indisponíveis]';}}
function renderEvents(){const opened=new Set([...$('#events').querySelectorAll('details[open]')].map(el=>el.closest('article').dataset.id));const rows=state.events.filter(event=>state.filter==='all'||event.type===state.filter);const fragment=document.createDocumentFragment();rows.forEach(event=>{const article=$node('article','event');article.dataset.id=event.id;article.dataset.type=event.type;const symbol=$node('div','event-icon');symbol.append(icon(event.type==='tool'?'tool':event.type==='complete'?'check':event.type==='error'?'stop':'spark'));const content=$node('div');const head=$node('div','event-head');const time=$node('time','',new Date(event.time).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}));time.dateTime=event.time;head.append($node('h3','',event.title),time);content.append(head,$node('p','',event.summary));const tags=$node('div','event-tags');if(event.tool)tags.append($node('span','event-tag',event.tool));tags.append($node('span','event-tag simulated',event.simulated?'simulado':'evento do agente'));content.append(tags);if(event.input!==undefined||event.output!==undefined){const details=$node('details');details.open=opened.has(event.id);details.append($node('summary','','Entrada e resultado'));if(event.input!==undefined)details.append($node('pre','','ENTRADA\n'+publicData(event.input)));if(event.output!==undefined)details.append($node('pre','','RESULTADO\n'+publicData(event.output)));content.append(details);}article.append(symbol,content);fragment.append(article);});if(!rows.length){const empty=$node('div','empty');empty.append($node('span','','↳'),$node('h3','',state.events.length?'Nenhum evento neste filtro.':'O próximo passo começa com você.'),$node('p','',state.events.length?'As próximas atividades aparecem aqui.':'Envie uma mensagem ou veja a demonstração na conversa.'));fragment.append(empty);}$('#events').replaceChildren(fragment);$('#activity-count').textContent=state.events.length;$('#export').disabled=!state.events.length;}
function addEvent(raw){const event={id:raw.id||crypto.randomUUID(),type:raw.type||'action',title:raw.title||'Atividade',summary:raw.summary||'',tool:raw.tool||'',input:raw.input,output:raw.output,time:raw.time||new Date().toISOString(),simulated:raw.simulated!==false};const existing=state.events.findIndex(item=>item.id===event.id);if(existing>=0)state.events[existing]=event;else state.events.push(event);if(state.events.length>150)state.events.shift();renderEvents();documentation.event(event);if(state.view!=='activity'){$('#event-dot').hidden=false;state.unread=true;}mood(event.type==='complete'?'done':event.type==='error'?'error':event.type==='tool'?'tool':'working',event.title);}
function message(role,text,scope=''){const article=$node('article','chat-message '+role);const meta=$node('div','chat-meta');meta.append($node('span','',role==='user'?'VOCÊ':'MIMO / AGENTE LOCAL'),$node('span','',new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})));const bubble=$node('div','chat-bubble',text);if(scope){const link=$node('div','message-scope');link.append(icon('link'),document.createTextNode(scope));bubble.append(link);}article.append(meta,bubble);if(role==='assistant')article.append($node('span','message-label',nativeMode?'RESPOSTA DO AGENTE · NO CELULAR':'RESPOSTA SIMULADA · PRÉVIA NO COMPUTADOR'));$('#conversation').append(article);state.messages.push({role,text,scope});if(state.messages.length>60){state.messages.shift();$('#conversation').firstElementChild?.remove();}$('#conversation').hidden=false;$('#welcome').hidden=true;$('#app').classList.add('has-conversation');return article;}
function active(value){state.active=value;$('#send').hidden=value;$('#send').disabled=nativeMode&&!connected;$('#stop').hidden=!value;$('#scope').disabled=value;$('#prompt').disabled=value;$('#active-task').hidden=!value;$('#watch-demo').disabled=value;document.querySelectorAll('[data-suggestion]').forEach(button=>button.disabled=value);if(!value){state.timers.forEach(clearTimeout);state.timers=[];clearInterval(state.clock);}}
function schedule(fn,delay){state.timers.push(setTimeout(fn,delay));}
function clearRun(){mascot.clearSpeech();state.timers.forEach(clearTimeout);clearInterval(state.clock);state.timers=[];state.events=[];$('#activity-time').textContent='00:00';renderEvents();state.sequence++;}
function startDemo(prompt,scope){clearRun();active(true);state.started=Date.now();state.clock=setInterval(()=>$('#activity-time').textContent=formatTime(Math.floor((Date.now()-state.started)/1000)),1000);message('user',prompt,scope);$('#prompt').value='';$('#char-count').textContent='0 / 2000';resizePrompt();view('chat');
 mascot.say('Demonstração: aqui aparecerão as descobertas verificadas pelo agente.','demo');
 const reading=Boolean(scope)||/https?:\/\//i.test(prompt);const url=scope||(prompt.match(/https?:\/\/[^\s]+/i)||[])[0]||'';
 documentation.start(url,prompt,true);
 const steps=reading?[
 {type:'action',title:'Pedido recebido',summary:'A interface enviaria seu pedido e o link ao agente que já existe no celular.',input:{prompt,scope:url,thinking:false},output:'Prévia: nenhum pedido foi enviado ao POCO.'},
 {type:'tool',title:'Abrindo a página',summary:'O coletor leria o conteúdo e reuniria as fontes da página.',tool:'crawl',input:{url},output:{status:'simulado',sources:[{url,title:'Página de exemplo'}],note:'Nenhuma requisição foi feita a este endereço.'}},
 {type:'summary',title:'Separando informação de instrução',summary:'O conteúdo da página é tratado como uma fonte de dados, sem virar instrução para o agente.',output:'Exemplo de resumo público da atividade.'},
 {type:'action',title:'Organizando a resposta',summary:'O modelo local prepararia uma resposta com o conteúdo consultado e as fontes.',output:'Huihui-POCO-4B-Q4_0 · Android / Termux'},
 {type:'complete',title:'Demonstração concluída',summary:'Agora você vê onde o link entra, como acompanha as ações e onde aparece a resposta.'}
 ]:[
 {type:'action',title:'Mensagem recebida',summary:'Seu texto entraria em /api/chat, usando o campo prompt do backend existente.',input:{prompt,scope:'',thinking:false}},
 {type:'summary',title:'Preparando a conversa',summary:'Para uma conversa sem alvo, o agente pode responder sem executar ferramentas.'},
 {type:'action',title:'Formulando a resposta',summary:'O modelo Huihui 4B faria a geração local, e a interface acompanharia /api/state.'},
 {type:'complete',title:'Demonstração concluída',summary:'A resposta aparece na conversa. As ações ficam na aba Atividade, e o dossiê na Documentação.'}
 ];
 steps.forEach((event,index)=>schedule(()=>{addEvent(event);if(index===steps.length-1){active(false);message('assistant',reading?'É aqui que eu entregaria a leitura do seu link — com um resumo, os pontos principais e as fontes.\n\nVocê pode acompanhar as ferramentas na aba Atividade e ver o resumo, as fontes e os achados na Documentação.\n\nEsta é uma demonstração da interface: não acessei o endereço nem executei o agente do celular.':'É aqui que a gente conversa. Você pode fazer uma pergunta, dar uma tarefa ou colocar uma URL no campo de link.\n\nO resultado virá do agente que já roda no seu POCO. Por enquanto, esta resposta é simulada para você testar a nova interface.');mascot.react();}},index*2100));
}
$('#composer').addEventListener('submit',event=>{event.preventDefault();if(state.active)return;const scope=$('#scope').value.trim();let prompt=$('#prompt').value.trim();if(!prompt&&scope)prompt='Leia esta página e resuma os pontos principais.';if(!prompt){toast('Escreva uma mensagem ou coloque um link para começar.');$('#prompt').focus();return;}if(scope){try{const url=new URL(scope);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error();}catch{toast('Use um link HTTP ou HTTPS válido, sem credenciais.');return;}}if(prompt.length>2000||scope.length>2000){toast('Use até 2.000 caracteres em cada campo.');return;}if(nativeMode){if(live.submit(prompt,scope)){$('#prompt').value='';resizePrompt();view('chat');}}else startDemo(prompt,scope);});
$('#stop').addEventListener('click',()=>{if(nativeMode){live.stop();return;}if(!state.active)return;active(false);addEvent({type:'error',title:'Demonstração interrompida',summary:'Você encerrou a simulação. Nenhum processo do celular foi alterado.'});message('assistant','Parei a demonstração. Você pode mandar outra mensagem quando quiser.');});
$('#watch-demo').addEventListener('click',()=>startDemo('Leia este link e me explique os pontos principais.','https://example.com'));
$('#active-task').addEventListener('click',()=>view('activity'));
function resizePrompt(){const input=$('#prompt');input.style.height='auto';input.style.height=Math.min(input.scrollHeight,100)+'px';$('#char-count').textContent=input.value.length+' / 2000';}
$('#prompt').addEventListener('input',resizePrompt);$('#prompt').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey&&(event.ctrlKey||event.metaKey)){event.preventDefault();$('#composer').requestSubmit();}});
$('#scope').addEventListener('input',()=>$('#clear-scope').hidden=!$('#scope').value);$('#clear-scope').addEventListener('click',()=>{$('#scope').value='';$('#clear-scope').hidden=true;$('#scope').focus();});
document.querySelectorAll('[data-suggestion]').forEach(button=>button.addEventListener('click',()=>{if(button.dataset.suggestion==='link'){$('#prompt').value='Leia este link e resuma os pontos principais.';$('#scope').focus();}else{$('#prompt').value='O que você consegue fazer no meu celular?';$('#prompt').focus();}resizePrompt();}));
document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{state.filter=button.dataset.filter;document.querySelectorAll('[data-filter]').forEach(other=>{other.classList.toggle('selected',other===button);other.setAttribute('aria-pressed',String(other===button));});renderEvents();}));
$('#motion').addEventListener('click',()=>{const paused=$('#motion').getAttribute('aria-pressed')!=='true';$('#motion').setAttribute('aria-pressed',String(paused));$('#motion').setAttribute('aria-label',paused?'Retomar animação do mascote':'Pausar animação do mascote');$('#motion').textContent=paused?'▷':'Ⅱ';document.body.classList.toggle('motion-paused',paused);mascot.setPaused(paused);});
const tools=[['↗','Leitura de páginas','Lê páginas e reúne fontes para o agente explicar.','crawl','ADAPTADOR'],['⌕','Inspeção HTTP','Observa resposta, tecnologia e cabeçalhos do alvo.','inspect_http','ADAPTADOR'],['⌁','Nmap','Identifica serviços expostos quando a tarefa exige.','nmap','INSTALADO'],['✳','Nuclei','Usa verificações do catálogo de templates instalado.','nuclei','INSTALADO'],['⋈','SQLMap','Investiga parâmetros e reúne evidências de SQLi.','sqlmap','INSTALADO'],['⟨⟩','HTTP e reflexão','Requisições dentro do escopo e marcadores inertes.','http_request · xss_probe','ADAPTADOR']];
tools.forEach(([symbol,name,description,id,status])=>{const card=$node('article','tool-card');const text=$node('div');text.append($node('h3','',name),$node('p','',description));card.append($node('span','tool-symbol',symbol),text,$node('span','tool-status',status));card.title=id;$('#tools-list').append(card);});
function openInfo(title,paragraphs){$('#dialog-title').textContent=title;$('#dialog-content').replaceChildren(...paragraphs.map(text=>$node('p','',text)));$('#info-dialog').showModal();}
$('#settings').addEventListener('click',()=>openInfo('Seu POCO. Uma nova cara.',[
 nativeMode?'Interface instalada no seu POCO, com o mascote animado e a conexão nativa ao agente. O backend existente foi preservado.':'Esta prévia foi criada no computador. Os envios são simulados.',
 nativeMode?'Mensagens, links, ferramentas e respostas vêm do agente local. A conexão é feita pelo aplicativo Android.':'A conversa aceita mensagem e link/alvo. Nesta prévia os envios são simulados.',
 'Acompanhe ações, ferramentas, evidências e resumos públicos na aba Atividade. O raciocínio interno privado não é exibido.',
 'As mensagens anteriores ficam apenas nesta aba. O backend recebe um pedido por vez e não aceita um histórico de conversa no contrato atual. A memória por projeto é um recurso separado.',
 nativeMode?'A Documentação reúne o resumo e as evidências reais de cada site nesta sessão. Exporte para guardar.':'A Documentação demonstra como serão organizados os resultados por site.',
 'O mascote usa imagens animadas com o visual da sua referência. Ele espera, lê, trabalha e comemora conforme a atividade. Toque para experimentar as animações. Você pode pausar; a interface também respeita movimento reduzido.'
]));
$('#memory-info').addEventListener('click',()=>openInfo('Memória por projeto.',[
 'O projeto do celular mantém escopo, sitemap, hipóteses e cobertura OWASP em SQLite, separados por origem do alvo.',
 'Essa memória pertence ao agente e é separada do histórico de conversa. Esta aba não lista ou modifica seus registros.',
 'O Mimo também guarda contagens e identificadores de caminhos e observações reproduzidas por site. Nas próximas visitas, consulta essa memória e compara o que reapareceu. Isso não altera os pesos do modelo nem transforma conteúdo de páginas em instruções.'
]));
$('#close-dialog').addEventListener('click',()=>$('#info-dialog').close());$('#dialog-done').addEventListener('click',()=>$('#info-dialog').close());
$('#export').addEventListener('click',()=>{const data={app:'POCO / Mimo',mode:nativeMode?'android-live':'local-preview',exportedAt:new Date().toISOString(),events:state.events};saveFile('poco-atividade.json',JSON.stringify(data,null,2),'application/json');toast(nativeMode?'Escolha onde salvar o registro.':'Registro exportado.');});
// Read-only adapter hook for the native host. Never consumes private reasoning fields.
let previousPhoneState=null;
window.PocoPreview=Object.freeze({receivePublicState(snapshot){if(!snapshot||typeof snapshot!=='object')return 0;const events=stateToPublicEvents(snapshot,previousPhoneState);documentation.receiveState(snapshot);previousPhoneState={phase:snapshot.phase,decision:snapshot.decision,updated_at:snapshot.updated_at,active:snapshot.active};events.forEach(event=>addEvent({...event,simulated:false}));return events.length;}});

if(nativeMode){
  document.body.classList.add('native-app');
  $('.demo-badge').textContent='NO CELULAR';
  $('.composer-caption>span').replaceChildren($node('i'),document.createTextNode(' CONECTANDO AO AGENTE'));
  $('#watch-demo').hidden=true;
  $('#stop').setAttribute('aria-label','Interromper execução');
  $('#settings').setAttribute('aria-label','Sobre o aplicativo');
  $('.catalog-note').textContent='Capacidades do POCO Agent. Execuções e resultados aparecem na aba Atividade.';
  $('#scope').value=window.PocoNative.savedScope();
  $('#clear-scope').hidden=!$('#scope').value;
  live=createLiveSession(window.PocoNative,{
    clear:clearRun,documentStart:(scope,prompt)=>documentation.start(scope,prompt,false),
    documentState:snapshot=>documentation.receiveState(snapshot),
    learning:snapshot=>mascot.learn(snapshot),
    message,updateMessage(article,text,error){if(!article)return;article.querySelector('.chat-bubble').textContent=text;article.classList.toggle('failed',error);},
    active(value,online){connected=online;if(value&&!state.active){state.started=Date.now();clearInterval(state.clock);state.clock=setInterval(()=>$('#activity-time').textContent=formatTime(Math.floor((Date.now()-state.started)/1000)),1000);}active(value);},phase:mood,event:addEvent,eventCount:()=>state.events.length,notify:toast,
    connection(online,detail){connected=online;$('.composer-caption>span').replaceChildren($node('i'),document.createTextNode(online?' AGENTE CONECTADO · NO CELULAR':' AGENTE DESCONECTADO'));if(!online)$('#activity-state').textContent=detail||'Abra o Termux para iniciar o agente.';}
  });
  window.PocoHost=Object.freeze({receive:snapshot=>live.receive(snapshot),connection:(ok,detail)=>live.connection(ok,detail),commandResult:(kind,ok,detail)=>live.commandResult(kind,ok,detail)});
  active(false);
  window.PocoNative.ready();
}

window.addEventListener('pagehide',()=>{active(false);mascot.dispose();});
