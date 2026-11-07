import { publicResponse } from './documentation.js';
import { stateToPublicEvents } from './phone-adapter.js';

export function createLiveSession(bridge, ui) {
  let online=false, pending=null, previous=null, lastStamp=-1, current=null;
  let response=null, lastPrompt='', lastScope='', wasActive=false, observedStamp=-1;
  function connection(connected, detail='') {
    online=Boolean(connected); ui.connection(online, detail);
    ui.active(Boolean(pending)||wasActive, online);
  }
  function begin(prompt, scope) {
    ui.clear(); ui.documentStart(scope, prompt); ui.message('user',prompt,scope);
    response=ui.message('assistant','Aguardando o agente…');
    lastPrompt=prompt; lastScope=scope; previous=null; current=null; lastStamp=-1;
  }
  function submit(prompt,scope) {
    if(!online) { ui.notify('Agente desconectado. Abra o Termux e tente novamente.'); return false; }
    if(pending||wasActive) return false;
    begin(prompt,scope);
    pending={prompt,scope,after:observedStamp,id:crypto.randomUUID()};
    ui.active(true,true); ui.phase('working','Enviando ao agente');
    try { bridge.sendMessage(JSON.stringify({prompt,scope,thinking:false,request_id:pending.id})); }
    catch { commandResult('send',false,'Não foi possível enviar ao agente.'); }
    return true;
  }
  function commandResult(kind, success, detail='') {
    if(kind==='export') {ui.notify(detail);return;}
    if(success) { if(kind==='stop')ui.notify('Interrupção solicitada ao agente.'); return; }
    if(kind==='send') {
      pending=null; wasActive=false;
      ui.updateMessage(response,'Não foi possível enviar: '+detail,true);
      ui.active(false,online); ui.phase('error','Falha no envio');
    }
    ui.notify(detail||'Não foi possível concluir a ação.');
  }
  function receive(snapshot) {
    if(!snapshot||typeof snapshot!=='object')return {ok:false};
    connection(true);
    const stamp=Number(snapshot.updated_at)||0;
    observedStamp=Math.max(observedStamp,stamp);
    if(pending) {
      if((snapshot.request_id? snapshot.request_id!==pending.id : snapshot.prompt!==pending.prompt||snapshot.scope!==pending.scope)||stamp<=pending.after) return {ok:true,pending:true};
      pending=null;lastPrompt=snapshot.prompt;lastScope=snapshot.scope||'';
    }
    if(!snapshot.prompt) { wasActive=Boolean(snapshot.active);ui.active(wasActive,online);return {ok:true,empty:true}; }
    if(stamp===lastStamp)return {ok:true,unchanged:true};
    const newRun=snapshot.prompt!==lastPrompt||snapshot.scope!==lastScope||(!wasActive&&snapshot.active&&current);
    if(newRun||!response)begin(snapshot.prompt,snapshot.scope||'');
    lastStamp=stamp;
    current=snapshot;
    ui.documentState(snapshot);
    ui.learning?.(snapshot);
    stateToPublicEvents(snapshot,previous).forEach(event=>ui.event({...event,simulated:false}));
    previous={phase:snapshot.phase,decision:snapshot.decision,updated_at:stamp,active:snapshot.active};
    const text=publicResponse(snapshot.content);
    const failed=Boolean(snapshot.error)||snapshot.phase==='Erro'||snapshot.phase==='Interrompido';
    ui.updateMessage(response,text||(failed?String(snapshot.error||snapshot.phase):snapshot.active?'O agente está trabalhando. Acompanhe na aba Atividade.':'O agente encerrou sem uma resposta textual.'),failed);
    wasActive=Boolean(snapshot.active);ui.active(wasActive,online);
    ui.phase(failed?'error':!wasActive?'done':snapshot.decision==='crawl'?'working':snapshot.decision&&snapshot.decision!=='answer'?'tool':'working',snapshot.phase||'Pronto');
    return {ok:true,active:wasActive,responseLength:text.length,events:ui.eventCount()};
  }
  function stop(){if(online&&wasActive)bridge.stop();}
  return {submit,stop,receive,connection,commandResult};
}
